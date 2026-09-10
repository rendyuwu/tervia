/**
 * The AI CLI agents offered by the tab strip's `+` -> Agent picker, and the
 * user's edits to them.
 *
 * Two things are user-editable and persisted (`tervia-cli-agents.json`, shared
 * across windows via a Tauri event like `agentsStore`):
 *   - a built-in's `command`, because the binary is often renamed or wrapped
 *     (`claude` -> `claude-start`), and its `pinned` flag;
 *   - whole custom agents, for CLIs Tervia doesn't ship a default for.
 *
 * `id` doubles as the detector's {@link AiCliKind} for built-ins, so a renamed
 * command still lights the right status badge - see `launchAgent`, which tags
 * the pane explicitly instead of relying on `TOOL_PATTERNS` matching whatever
 * the user typed here.
 */
import { createRecoveredStore } from "@/lib/recoveredStore";
import type { StoreRecovery } from "@/lib/storeRecovery";
import { create } from "zustand";
import { matchTool } from "./aiCliDetector";
import type { AiCliKind } from "./aiCliStatus";

/**
 * Cap on one Agent spawn, counting repeats: the same agent can be picked more
 * than once (three Claude panes is a normal thing to want). Equal to
 * `MAX_PANES_PER_TAB`, so a full spawn fills the tab exactly and leaves no room
 * for a further split - `newPaneGroupTab` clamps to that cap either way.
 */
export const MAX_AGENT_SPAWN = 6;

export type CliAgent = {
  /** Built-ins use their `AiCliKind` verbatim; custom agents get `cli-<rand>`. */
  id: string;
  name: string;
  /** Typed at the shell prompt to start the agent. */
  command: string;
  /** Sorts to the top of the Agent picker. */
  pinned?: boolean;
  builtIn: boolean;
};

/** A shipped agent, whose id is pinned to a detector kind at compile time. */
type BuiltinCliAgent = CliAgent & { id: AiCliKind; builtIn: true };

/** The shipped roster. Order is the picker order among unpinned agents. */
export const BUILTIN_CLI_AGENTS: readonly BuiltinCliAgent[] = [
  { id: "claude", name: "Claude CLI", command: "claude", builtIn: true },
  { id: "codex", name: "Codex CLI", command: "codex", builtIn: true },
  { id: "opencode", name: "opencode", command: "opencode", builtIn: true },
  { id: "pi", name: "Pi", command: "pi", builtIn: true },
  { id: "copilot", name: "GitHub Copilot", command: "copilot", builtIn: true },
  { id: "grok", name: "Grok CLI", command: "grok", builtIn: true },
  { id: "gemini", name: "Gemini CLI", command: "gemini", builtIn: true },
] as const;

/**
 * Detector kind to tag a launched pane with. A built-in keeps its kind however
 * its command was renamed; a custom agent is classified from its command, so
 * `claude --resume` still gets a badge and `my-wrapper` simply gets none.
 *
 * Resolved by lookup rather than casting `agent.id`, so a persisted custom agent
 * that somehow carries a built-in id still yields a kind that is really an
 * `AiCliKind` instead of an unchecked assertion.
 */
export function agentToolKind(agent: CliAgent): AiCliKind | null {
  const builtin = BUILTIN_CLI_AGENTS.find((a) => a.id === agent.id);
  if (builtin) return builtin.id;
  return matchTool(agent.command);
}

// ---- persistence ----

const STORE_PATH = "tervia-cli-agents.json";
const KEY_CUSTOM = "customCliAgents";
const KEY_OVERRIDES = "builtinCliAgentOverrides";
const CHANGED_EVENT = "tervia://cli-agents-changed";

/**
 * The agent file, with crash recovery in front of it.
 *
 * In the recovered-store family for what `commit` gives it rather than for
 * corruption alone: a custom agent's row and a built-in's override are two keys,
 * and the file is written whole, so neither edit can land half way.
 */
const io = createRecoveredStore({
  path: STORE_PATH,
  loadKey: KEY_CUSTOM,
  changedEvent: CHANGED_EVENT,
});

/** Run the recovery pass and hand back what the user should be told, once. */
export function ensureLoaded(): Promise<StoreRecovery | null> {
  return io.ensureLoaded();
}
/** Drain the notice slot again, for a note that lands after startup. */
export function takeRecoveryNotice(): StoreRecovery | null {
  return io.takeRecoveryNotice();
}
/** Another window committed the agent file. */
export function onCliAgentsChanged(cb: () => void): Promise<() => void> {
  return io.onChanged(cb);
}

/** Per-built-in user edits. Only the editable fields are stored. */
export type CliAgentOverrides = Record<string, { command?: string; pinned?: boolean }>;

async function load(): Promise<{ custom: CliAgent[]; overrides: CliAgentOverrides }> {
  // Two gets, one file read: the store reads the whole file and answers both
  // from its cache. This used to be `entries()` to spend one IPC roundtrip
  // instead of two, which is no longer the trade being made.
  const [custom, overrides] = await Promise.all([
    io.get<CliAgent[]>(KEY_CUSTOM),
    io.get<CliAgentOverrides>(KEY_OVERRIDES),
  ]);
  return { custom: custom ?? [], overrides: overrides ?? {} };
}

export function newCliAgentId(): string {
  return `cli-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

/** Built-ins with overrides applied, then custom agents, pinned ones first. */
export function effectiveCliAgents(custom: CliAgent[], overrides: CliAgentOverrides): CliAgent[] {
  const builtins = BUILTIN_CLI_AGENTS.map((a) => {
    const o = overrides[a.id];
    if (!o) return a;
    return { ...a, command: o.command?.trim() || a.command, pinned: o.pinned ?? a.pinned };
  });
  const all = [...builtins, ...custom];
  // Stable partition, so within each group the declared/creation order holds.
  return [...all.filter((a) => a.pinned), ...all.filter((a) => !a.pinned)];
}

type CliAgentsState = {
  hydrated: boolean;
  customAgents: CliAgent[];
  overrides: CliAgentOverrides;
  /** Built-ins (overrides applied) plus custom agents, pinned first. */
  all: () => CliAgent[];
  hydrate: () => Promise<void>;
  /** Upsert any agent. Built-ins land in `overrides`; others in `customAgents`. */
  upsert: (agent: CliAgent) => void;
  /** Remove a custom agent (no-op on built-ins). */
  remove: (id: string) => void;
  togglePinned: (id: string) => void;
  /** Drop a built-in's edits, restoring its shipped command. */
  resetBuiltin: (id: string) => void;
  hasOverride: (id: string) => boolean;
};

let initialized = false;

/**
 * Write one key through, then tell the other window to re-read. Callers fire
 * this and forget, so a failed write is reported here rather than surfacing as
 * an unhandled rejection; the in-memory state stays as the user left it and the
 * next edit retries the whole key.
 */
function persist(key: string, value: unknown): void {
  void io
    .enqueueWrite(async () => {
      await io.set(key, value);
      // Flushes, snapshots and emits `CHANGED_EVENT` - the three used to be
      // written out here and one of them is easy to forget.
      await io.commit();
    })
    .catch((err: unknown) => {
      console.error(`cliAgents: failed to persist ${key}`, err);
    });
}

function isBuiltinId(id: string): boolean {
  return BUILTIN_CLI_AGENTS.some((a) => a.id === id);
}

export const useCliAgentsStore = create<CliAgentsState>((set, get) => ({
  hydrated: false,
  customAgents: [],
  overrides: {},
  all: () => effectiveCliAgents(get().customAgents, get().overrides),
  hydrate: async () => {
    if (initialized) return;
    initialized = true;
    // A failed read must not take the picker down with it: the built-in roster
    // is a pure constant, so an unreadable store just means "no user edits yet"
    // and every agent still launches.
    try {
      const { custom, overrides } = await load();
      set({ customAgents: custom, overrides });
    } catch (err) {
      console.error("cliAgents: failed to load saved agents; using defaults", err);
    }
    set({ hydrated: true });
    // `onChanged` rather than a bare `listen`: it drops the store's cache before
    // handing the event on, so this re-read sees the file the other window wrote
    // instead of the one this window last read.
    void io.onChanged(() => {
      void (async () => {
        try {
          const fresh = await load();
          set({ customAgents: fresh.custom, overrides: fresh.overrides });
        } catch (err) {
          console.error("cliAgents: failed to re-read after a change", err);
        }
      })();
    });
  },
  upsert: (agent) => {
    if (isBuiltinId(agent.id)) {
      const shipped = BUILTIN_CLI_AGENTS.find((a) => a.id === agent.id)!;
      const next: CliAgentOverrides = {
        ...get().overrides,
        [agent.id]: {
          // Store only what differs, so a later default change still lands.
          ...(agent.command.trim() && agent.command.trim() !== shipped.command
            ? { command: agent.command.trim() }
            : {}),
          ...(agent.pinned ? { pinned: true } : {}),
        },
      };
      set({ overrides: next });
      persist(KEY_OVERRIDES, next);
      return;
    }
    const list = get().customAgents;
    const idx = list.findIndex((a) => a.id === agent.id);
    const next = idx === -1 ? [...list, agent] : list.map((a) => (a.id === agent.id ? agent : a));
    set({ customAgents: next });
    persist(KEY_CUSTOM, next);
  },
  remove: (id) => {
    if (isBuiltinId(id)) return;
    const next = get().customAgents.filter((a) => a.id !== id);
    set({ customAgents: next });
    persist(KEY_CUSTOM, next);
  },
  togglePinned: (id) => {
    const current = get()
      .all()
      .find((a) => a.id === id);
    if (!current) return;
    get().upsert({ ...current, pinned: !current.pinned });
  },
  resetBuiltin: (id) => {
    const existing = get().overrides[id];
    if (!isBuiltinId(id) || !existing?.command) return;
    // Only the command is restored. The pin is a separate preference the user
    // set deliberately, and this button is labelled "restore default command".
    const next = { ...get().overrides };
    if (existing.pinned) next[id] = { pinned: true };
    else delete next[id];
    set({ overrides: next });
    persist(KEY_OVERRIDES, next);
  },
  hasOverride: (id) => {
    const o = get().overrides[id];
    return !!o && o.command !== undefined;
  },
}));
