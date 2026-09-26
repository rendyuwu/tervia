# TERVIA.md

Agent memory and contributor reference for Tervia. Code map (module tables,
data files, flows): [ARCHITECTURE.md](ARCHITECTURE.md). Accepted limitations:
[KNOWN-LIMITS.md](KNOWN-LIMITS.md). Build and PR rules:
[CONTRIBUTING.md](CONTRIBUTING.md).

## Project

|                 |                                                                                                                   |
| --------------- | ----------------------------------------------------------------------------------------------------------------- |
| Version         | 0.1.0                                                                                                             |
| Repo / site     | `github.com/rendyuwu/tervia` / `https://tervia.rendy.dev`                                                         |
| Stack           | Tauri 2 + Rust (`portable-pty`, `russh`) with React 19 + TS + xterm.js (WebGL)                                    |
| Bundle id       | `dev.rendy.tervia` (dev profile: `dev.rendy.tervia.dev`)                                                          |
| Crates/binaries | `tervia` (lib `tervia_lib`, GUI binary `TerviaApp`); `tervia-cli` (Windows console launcher, binary `tervia.exe`) |
| Secret services | `tervia-hosts`, `tervia-vault`, `tervia-sync`                                                                     |
| Package manager | pnpm                                                                                                              |

## Conventions

- **Icons**: `lucide-react`, imported by name. Brand marks: `components/BrandIcon.tsx`;
  agent marks: `components/CliAgentIcon.tsx`; file/folder glyphs: the Catppuccin set,
  dynamically imported by `explorer/lib/iconResolver.ts`.
- **Styling**: Tailwind v4 (`@theme` blocks in `src/styles/globals.css` and
  `shadcn-tailwind.css`, no `tailwind.config.*`); `cn()` from `@/lib/utils`.
  shadcn/ui components are generated, not hand-edited.
- **Imports**: always `@/...`, never a relative path across modules
  (`scripts/check-imports.mjs`).
- **Types**: no `any` in TypeScript.
- **Paths**: split with `pathSegments` / `basename` from `@/lib/path`; the
  canonical frontend form is forward-slash. OSC 7 arrives forward-slash after
  `parseOsc7` strips the `/C:` drive prefix.
- **Terminal input**: send `\r` (CR) for Enter, not `\n` (PowerShell needs CR).
- **Cross-platform paths**: HOME/cache/data via the `dirs` crate
  (`app_data_dir` in `src-tauri/src/modules/ids.rs`), never raw env vars.
- **Window styling**: macOS gets native traffic lights via an Overlay title
  bar; Linux and Windows are borderless with React `WindowControls`. Windows
  adds `apply_windows_frame_fixes` (main window only, maximize-clamp and
  minimize), `disable_windows_corner_rounding`, and
  `disable_browser_accelerator_keys` so WebView2 does not eat Ctrl+W / Ctrl+R.
  macOS drops "Close Window" from the app menu so Cmd+W closes a tab.
- **Docs and prose**: no em-dashes (commas, colons, or parentheses instead).
  No emoji in docs, code, or commits.
- **Comments cite only what a clone can reach**: a file `git ls-files` returns,
  a symbol, an upstream project's public tracker named by project
  (`xterm.js #4054`), or a pinned dependency's own source (crate, version,
  symbol, never a line number). Never cite this project's own planning docs,
  issue numbers, section numbers, `/tmp` paths, dates, or commit hashes.
  One carve-out: a comment may name a file that is gone when the deletion
  itself is the sentence's subject, in the past tense ("once X was deleted, Y
  became unreachable").
- **Cite a symbol, not a line**: a line number goes stale the moment another
  commit touches that file. `scripts/citation-format-verify.ts` fails on a
  `file:line` inside a comment in `src/`, `src-tauri/src/`, or `scripts/`, and
  on a backticked path that resolves to no file in the tree.
- **An accepted state goes in [KNOWN-LIMITS.md](KNOWN-LIMITS.md)**, not a
  planning document: an entry is three parts, what is accepted, which file and
  symbol carries it, and the condition that would change the answer. The
  symbol should point back at the entry.

## Area rules

### SSH (`src-tauri/src/modules/ssh/`)

- Auth precedence in `authenticate_hop` (`session.rs`): `use_agent` wins, then
  a private key paired with an OpenSSH certificate, then a plain private key,
  then a password.
- A new host's `HostKeyPrompt` pauses the handshake before any credential is
  sent; `ssh_confirm_host_key(prompt_id, accept)` resumes or aborts it.
- `HOST_KEY_ALGOS` drops bare `ssh-rsa` (SHA-1) from russh's default host-key
  set. `jumps.ts`'s `resolveJumpHops` walks hops in connect order (entry host
  first) capped at `MAX_JUMP_HOPS = 16`. Remote git arguments are
  `shell_quote`d (`ssh/mod.rs`) because a remote OSC 7 cwd is
  attacker-controlled if the host is compromised.

### Shell integration (`src-tauri/src/modules/pty/scripts/`)

- Shells emit OSC 7 (cwd) and OSC 133 A/B/C/D (prompt boundaries), parsed by
  `terminal/lib/osc-handlers.ts`. OSC 8888 opens a file in an editor tab
  (`tervia_open`, alias `tp`), OSC 8889 spawns a tab, OSC 9;4 carries AI-CLI
  progress. Every spawned shell gets `TERVIA_TERMINAL=1`.
- Generated rc files live under `~/.cache/tervia/shell-integration/`: zsh
  (`ZDOTDIR`, preserving the user's own as `TERVIA_USER_ZDOTDIR`), bash
  (`--rcfile`), fish (`--init-command`). Windows: pwsh 7+, falling back to
  powershell 5.1, then `cmd.exe` with no integration.
- `pty/shell_init.rs` is split into `#[cfg(unix)]` / `#[cfg(windows)]` arms;
  keep new platform code in the matching arm.

### PTY daemon (`src-tauri/src/modules/pty_daemon/`)

- Length-prefixed JSON, version-gated via `Hello` (`PROTOCOL_VERSION = 1`);
  push events (`Data`/`Exit`) carry no `req_id`.
- Socket: Unix `$XDG_RUNTIME_DIR/tervia-ptyd.sock` (fallback
  `$TMPDIR/tervia-ptyd-<USER>.sock`), Windows `tervia-ptyd-<fnv1a(USERNAME)>`
  named pipe (`paths.rs`).
- Scrollback is a per-session ring capped at 1 MiB (`SCROLLBACK_CAP`,
  `server.rs`), replayed as one `AttachOk`. Idle self-shutdown after 24h
  (`TERVIA_PTYD_IDLE_SECS` overrides). Logs at
  `<data_dir>/<BUNDLE_ID>/logs/tervia-ptyd.log` (`TERVIA_PTYD_LOG=debug`).

### Windows PTY (`src-tauri/src/modules/pty/`)

- `SPAWN_LOCK` (`session.rs`) is a `Mutex` gating ConPTY lifecycle across
  `spawn()` and `drop_session()`, so `ClosePseudoConsole` cannot race a
  sibling's openpty.
- Each ConPTY child joins a Job Object with `KILL_ON_JOB_CLOSE` (`job.rs`), so
  dropping the Job kills the whole subtree, not just the immediate child.
- `apply_common` (`shell_init.rs`) rewrites the frontend's forward-slash cwd to
  backslashes under `#[cfg(windows)]` before handing it to ConPTY.

### Tabs and leaves (`src/modules/terminal/lib/panes.ts`)

- Five `leafKind`s: `terminal` (local PTY, or a remote shell when `hostId` is
  set), `editor` (file, local or remote; `hostId` is the frozen stable half of
  a remote identity), `board` (stateless AI-CLI kanban, rebuilt every render),
  `rdp` (canvas, holds only a reference to a saved host), `page` (Hosts only).
- Any leaf can pop into a floating OS window (`panes/floatHost.ts` ->
  `open_float_window` -> `float.html`), mirrored over Tauri events, not shared
  React state.

### Closing (`tabs/lib/closable.ts`)

- `leafCloseRefusal` / `tabCloseRefusal` refuse a `page` leaf (permanent) and
  the last entry in the workspace (permanent). Every close path (tab-strip X,
  pane-header X, `Ctrl+Shift+X` / `Ctrl+W`) must consult them; a refusal hides
  the X rather than disabling it, with no confirmation dialog for either case.
- `leafCloseConfirmReason` / `tabCloseConfirmReason` ask `"unsaved"` (dirty
  editor) or `"running"` (foreground terminal command) only after the refusal
  check passes; unsaved wins when a tab is both.

### Rail views (`tabs/lib/pages.ts`)

- Only Hosts is a tab. Vault, Port Forwarding, and Known Hosts
  (`RAIL_VIEW_KINDS`) are views shown over the tab area
  (`app/components/RailViewArea.tsx`); activation is not persisted across a
  relaunch.
- `focusTabView` is the only way `activeId` moves and always clears the view
  (including when the id does not change). The two close paths use
  `rehomeTabView` instead, which keeps the view up: closing a tab is not a
  request to leave Vault or Known Hosts.

### Keyboard owner and modal gate (`src/modules/shortcuts/lib/`)

- `yieldsToRawKeyboard` (`keyboardOwner.ts`): a focused terminal or RDP pane
  (`KEYBOARD_OWNING_SURFACES`) keeps bare-Ctrl and bare-Alt chords, except the
  ids in `FIRES_OVER_RAW_KEYBOARD` (`pane.splitRight`, `pane.focusNext`,
  `pane.focusPrev`) and while a rail view covers the tab area.
- No catalogued shortcut fires while a `Dialog`/`AlertDialog` is open
  (`modalRegistry.ts`). The registry is a stack; only the command palette's own
  chord is exempt, and only while the palette is topmost.

### Hosts, vault, credential moves (`src/modules/hosts/`, `src/modules/vault/`)

- Every integrity rule for a saved host lives in `hosts/store.ts`, never in a
  dialog: `assertBindingOwner` runs on every upsert (stops a spread-copied host
  authenticating with the source's secrets), a jump/tunnel target must be an
  SSH host with no cycle, and `deleteHost` releases every account it names.
- `duplicateHost` copies secrets for both protocols via `secrets_copy`
  (in-process, never through JS) but never the pinned server key; a
  vault-bound source's binding is shared, not duplicated.
- `vault/resolve.ts` is the one place a binding becomes a keychain reference
  the connect path dereferences host-side. Deleting an identity or key is
  refused while a host or group still references it (`VaultInUseError`).

### AI CLI detection (`src/modules/terminal/lib/`)

- `aiCliDetector.ts` classifies a known third-party CLI's command line and
  tracks `idle` / `working` / `blocking` / `done`; `done` holds as a breathing
  badge until the terminal is focused or typed in.
- `cliAgents.ts` owns the pickable agent list (`tervia-cli-agents.json`); the
  tab strip's `+ -> Agent` picker spawns up to `MAX_AGENT_SPAWN = 6` panes at
  once.

### Formatters (`src/modules/editor/lib/formatters/`)

- `builtin` (`prettier.ts`) lazy-imports Prettier 3 standalone, layering
  bundled defaults, then `.editorconfig`, then a project `.prettierrc*` /
  `package.json#prettier`. `external` (`external.ts` -> `fmt_run_external`)
  direct-spawns a tool with presets in `presets.ts`.
- `.prettierrc.{js,cjs,mjs,yaml,yml}` are not readable in builtin mode; use
  `external` with `prettier --stdin-filepath ${file}`.

## Workflow

- CI (`.github/workflows/ci.yml`) runs, frontend job: `pnpm run lint:imports`,
  `pnpm run typecheck:scripts`, `pnpm run format:check`, `pnpm run verify`,
  `pnpm exec tsc --noEmit`, `pnpm build`; rust job: `cargo fmt --all -- --check`,
  `cargo check --all-targets --locked`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked`.
- `pnpm run verify [substring]` runs `scripts/*-verify.ts`, auto-globbed by
  `scripts/verify-all.mjs` (a new file needs no registration). Modules meant to
  be exercised here stay free of xterm/Tauri imports at module scope, or take
  their IO as an injected port, so plain node can load them.
- `pnpm tauri:dev` uses `tauri.dev.conf.json` (`dev.rendy.tervia.dev`),
  isolating stores, the PTY socket, and logs in a `.dev` data dir. Plain
  `pnpm tauri dev` split-brains: `ids::BUNDLE_ID` is `.dev`-suffixed in any
  debug build while the frontend's store paths follow the config identifier.
  Set `TERVIA_PTYD_IDLE_SECS=60` when iterating on daemon code (default 24h).
- `tervia` CLI (`cli.rs`): `tervia <path>` opens a folder or file in the
  running window via single-instance forward; `--version` / `--help` print
  before Tauri boots, `--update` is drained by the frontend via
  `cli_take_initial_update_request`. Windows ships a console-subsystem
  `tervia.exe` launcher (`tervia-cli/`) ahead of the GUI's `TerviaApp.exe` on
  PATHEXT. A PATH shim (`~/.local/bin/tervia`) is installed from Settings and
  self-heals on launch.
- Release: a tag matching `v*` triggers `.github/workflows/release.yml`, which
  builds signed updates and a draft GitHub Release; notes are generated from
  `CHANGELOG.md` via `scripts/release-notes.mjs`. The file holds only the
  latest release; every earlier version lives in GitHub Releases, so a new
  draft replaces the old section instead of stacking on it.

## Gotchas

- `tauri.conf.json` sets `"removeUnusedCommands": true`, so a command with no
  frontend `invoke` call site can be stripped from a release build. Commands
  shipped with no caller are listed in `UNINVOKED`
  (`scripts/command-registry-verify.ts`), which fails if a command loses its
  last caller without an entry, or an entry gains one. `secrets_get_all` is
  `(service, accounts[])`, one service per call, so a batch spanning
  host-owned and vault-owned secrets is two calls.
- `git_run` and `ssh_git` share `check_args`, an allowlist of subcommands plus
  a NUL-byte guard; remote arguments are additionally single-quoted.
- The Settings window is denylisted from `tauri-plugin-window-state`, and
  `VISIBLE` is stripped from the restored state flags so the main window can
  call `show()` after first paint instead of flashing a transparent shadow.
- `capabilities/*.json` still list a `debug` window; there is no `debug.html`
  and no code creating one.
