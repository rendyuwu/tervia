# Contributing

Issues and PRs welcome. Code map: [ARCHITECTURE.md](ARCHITECTURE.md).
Code rules and gotchas: [TERVIA.md](TERVIA.md), read it before a PR.

## Setup

Rust stable, Node 20.19+ (`.nvmrc` pins 24, what CI uses), pnpm, and
[Tauri's prerequisites](https://tauri.app/start/prerequisites/).

```bash
pnpm install
pnpm tauri:dev   # own bundle id and data dir; never touches an installed Tervia
```

## Before a PR

CI runs all of these:

```bash
pnpm lint:imports        # no relative imports across modules
pnpm typecheck:scripts
pnpm format:check        # Prettier (fix: pnpm format)
pnpm verify              # scripts/*-verify.ts behaviour checks
pnpm typecheck
pnpm build
pnpm lint:rust           # cargo fmt --check + clippy -D warnings (fix: pnpm fmt:rust)
cd src-tauri && cargo test --workspace
```

Touched `src-tauri/`? Build a bundle once: `pnpm tauri build`. CI also builds
installers for every OS on each PR.

## Branches and PRs

- Branch off `dev`, open the PR against `dev`. `main` only receives `dev`.
- Prefixes: `feat/`, `fix/`, `chore/`, `docs/`, `perf/`.
- PRs are squash-merged; the title is the commit, in [Conventional Commits](https://www.conventionalcommits.org/) form: `fix(sftp): keep the tree open after a rename`.
- One change per PR. Open an issue first for anything non-trivial.
- Fill in the PR template.

## Scope

- Yes: bug fixes, SSH, RDP, forwarding, SFTP, backup and sync, the local workspace they need.
- No: telemetry, AI features, an extension API, an in-app browser, a default sync server, hardcoded credentials.
- Big dependency for a small win: no. Prefer nothing that adds a background thread, a poll loop or an unbounded buffer.

## Security

Do not open an issue. See [SECURITY.md](SECURITY.md).

## License

Contributions are Apache-2.0 ([LICENSE](LICENSE)).
