# Changelog

All notable changes to **Tervia**. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-`1.0`, minor bumps may include breaking
changes).

> Tervia is a fork of [IlhamriSKY/TEDI](https://github.com/IlhamriSKY/TEDI) at
> **v0.4.22**, which is itself a fork of
> [crynta/terax-ai](https://github.com/crynta/terax-ai) at **Terax v0.5.9**.
> The version series restarts at `0.1.0`, so nothing before this file belongs
> to Tervia. For what shipped up to the fork point, see
> [TEDI's CHANGELOG](https://github.com/IlhamriSKY/TEDI/blob/main/CHANGELOG.md)
> and, before that,
> [Terax's](https://github.com/crynta/terax-ai/blob/main/CHANGELOG.md). The git
> history in this repository is intact back through both, so `git log` and
> `git blame` still reach the original commits.

## [Unreleased]

### Added

- Nothing yet. The first release will be `0.1.0`.

### Changed

- **Scope narrowed to remote machines.** Tervia keeps SSH, port forwarding,
  SFTP and the encrypted connection backup, plus the local terminal, editor,
  explorer, panes, tabs and workspaces those need. RDP and end-to-end
  encrypted sync are planned and not built yet.

### Removed

Relative to TEDI v0.4.22:

- The AI agent and everything around it: providers, MCP, sub-agents,
  autocomplete, the AI diff tab and the AI settings sections. Detection and
  spawning of third-party agent CLIs inside a terminal stays — that is
  terminal functionality, not an AI feature.
- The extension system: host, panels, marketplace, permissions, the `ext` CLI
  subcommand and the extension backend. There is no extension API.
- The in-app preview browser and its Rust backend.
- The Source Control panel. Git decorations in the file explorer and the branch
  display in the workspaces panel are unaffected.
- The task scheduler.
- The `theme` and headless `--update` CLI subcommands. `tervia [PATH]`,
  `--help`, `--version` and `--update` remain; `--update` now needs the window
  to open.
