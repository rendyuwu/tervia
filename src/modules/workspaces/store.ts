import type { StoreRecovery } from "@/lib/storeRecovery";
import type { AiCliKind } from "@/modules/terminal/lib/aiCliStatus";
import type { PageKind } from "@/modules/terminal/lib/panes";
import { create } from "zustand";

import { createTauriWorkspacesStoreIo, KEY_ACTIVE, KEY_LIST } from "./adapters";

// Saved on-disk shape. Persists only what's needed to reconstruct tabs on
// next launch. Terminals respawn at their saved cwd; editors reopen the path.

export type SavedTerminalLeaf = {
  kind: "leaf";
  leafKind: "terminal";
  cwd?: string;
  /** SSH connection id for SSH-bound leaves. */
  sshConnectionId?: string;
  /** FIFO chip number. Persisted so "Terminal 3" stays the same after restart. Backfilled by `useTabs.ts` for older state. */
  terminalOrdinal?: number;
  /** Per-pane terminal theme override (a `TERMINAL_PRESETS` id). Persisted so a
   *  pane keeps its chosen palette across restart. Absent = follow global. */
  terminalThemeId?: string;
  /**
   * Daemon-owned PTY UUID. When present on next launch the restore path
   * calls `pty_attach` to resume the shell with its scrollback; on attach
   * failure (daemon was killed, system rebooted) the leaf falls back to a
   * fresh `pty_open`. Absent on SSH leaves and on builds where the daemon
   * backend is unavailable.
   */
  ptyId?: string;
  /**
   * Last program-set window title (OSC 0/2) captured from the live xterm -
   * e.g. a running agent's task or a TUI's filename. Persisted so the
   * Workspaces panel can show it next to the folder name for INACTIVE
   * workspaces too; live titles only exist for the active workspace's
   * terminals. May be stale after a restart until the workspace is reopened
   * and its terminals go live again.
   */
  title?: string;
  /**
   * AI CLI kind that was running in this terminal at snapshot time (only
   * persisted for reattachable local leaves, i.e. alongside `ptyId`). On
   * restore it pre-activates the detector so a still-running agent shows its
   * working/blocking badge immediately after reattach instead of going dark.
   */
  activeTool?: AiCliKind;
  /**
   * User-chosen tab name from the tab's right-click "Rename". Distinct from
   * `title` above, which is the program-set OSC title and is derived, not
   * chosen: this one is the user's and must survive a restart.
   */
  customTitle?: string;
};

export type SavedEditorLeaf = {
  kind: "leaf";
  leafKind: "editor";
  path: string;
  /**
   * Saved SSH connection id when this file lives on a remote host. `path` is
   * then a path on THAT host, never on the local disk. The live russh session
   * number is deliberately not persisted (it is dead after a restart, and the
   * counter restarts from 1, so it would point at whichever host connected
   * first); the pane re-resolves this id to a live session instead.
   * Absent = local file, which is every leaf written before this field existed.
   */
  sshConnectionId?: string;
  /** Display label for the remote host, shown while the leaf waits to rebind. */
  sshHostLabel?: string;
  /** User-chosen tab name from the tab's right-click "Rename". */
  customTitle?: string;
};

/**
 * LEGACY, read-only. The embedded browser was removed after v0.4.22, so nothing
 * writes this shape any more - but a layout saved by an older build still holds
 * them, and dropping the variant from the union would make `savedToNode`
 * un-narrowable. It restores as an empty terminal leaf so the tree keeps its
 * shape and saved split sizes.
 */
export type SavedBrowserLeaf = {
  kind: "leaf";
  leafKind: "browser";
  url: string;
  browserOrdinal?: number;
  customTitle?: string;
};

/**
 * An RDP pane. Holds a reference to a saved connection and nothing else: the
 * host, credentials and desktop size all live on the connection row, so there
 * is no secret and nothing host-shaped in the workspace file.
 *
 * There is deliberately no session id to restore. An RDP session cannot be
 * reattached the way a local PTY can - `ptyId` has no counterpart here - so the
 * leaf comes back and dials again, which is exactly how a restored SSH leaf
 * behaves.
 */
export type SavedRdpLeaf = {
  kind: "leaf";
  leafKind: "rdp";
  /** Id of a saved host in `hosts/store.ts`. A leaf whose host has since been
   *  deleted restores anyway and reports it in the pane, rather than vanishing
   *  from the layout without explanation. */
  rdpConnectionId: string;
  /** Persisted from day one even though `"preset"` is the only value, so adding
   *  `"fit"` needs no migration of everyone's saved workspaces. */
  sizeMode: "preset";
  /** User-chosen tab name from the tab's right-click "Rename". */
  customTitle?: string;
};

/**
 * The workspace Board pane. Holds nothing: its columns are rebuilt from the
 * live tab tree, so existence is the whole of its saved state. That is what
 * lets a pane tab containing one be persisted normally.
 */
export type SavedBoardLeaf = {
  kind: "leaf";
  leafKind: "board";
  /** User-chosen tab name from the tab's right-click "Rename". */
  customTitle?: string;
};

/**
 * A rail-opened page (Hosts, Vault, Port Forwarding). Holds nothing but which
 * page it is: like the Board, existence is the whole of its saved state.
 */
export type SavedPageLeaf = {
  kind: "leaf";
  leafKind: "page";
  page: PageKind;
  /** User-chosen tab name from the tab's right-click "Rename". */
  customTitle?: string;
};

export type SavedPaneNode =
  | SavedTerminalLeaf
  | SavedEditorLeaf
  | SavedRdpLeaf
  | SavedBrowserLeaf
  | SavedBoardLeaf
  | SavedPageLeaf
  | {
      kind: "split";
      dir: "row" | "col";
      children: SavedPaneNode[];
      /** Per-child size percentages (0..100), so restore keeps divider positions. */
      sizes?: number[];
    };

export type SavedPaneTab = {
  kind: "pane";
  title?: string;
  paneTree: SavedPaneNode;
  /** Index of the active leaf when reading from `leaves(paneTree)`. */
  activeLeafIndex: number;
};

/**
 * LEGACY, read-only. A standalone browser ("preview") tab from before browsers
 * became pane leaves, and before the embedded browser was removed entirely.
 * `savedToTab` restores it as an empty terminal pane.
 */
export type SavedPreviewTab = {
  kind: "preview";
  url: string;
  title?: string;
};

export type SavedTab = SavedPaneTab | SavedPreviewTab;
// ai-diff tabs are session-only. Never persisted.

export type Workspace = {
  id: string;
  name: string;
  tabs: SavedTab[];
  activeTabIndex: number;
};

type State = {
  hydrated: boolean;
  workspaces: Workspace[];
  activeId: string | null;
};

type Actions = {
  hydrate: () => Promise<void>;
  /** Force a synchronous-as-possible write of the current state to disk.
   *  Called on window close so a just-closed pane / latest layout is durable
   *  before the app quits (the per-change save is fire-and-forget). */
  flush: () => Promise<void>;
  setWorkspaces: (workspaces: Workspace[]) => void;
  setActiveId: (id: string | null) => void;
  /** Create an empty workspace. Caller must save prior tabs and call setActiveId to switch. */
  createWorkspace: (name: string) => Workspace;
  renameWorkspace: (id: string, name: string) => void;
  removeWorkspace: (id: string) => void;
  /** Replace a workspace's saved tabs. Used before a switch. `liveTabCount` is
   *  the number of LIVE tabs the snapshot came from (before serialization drops
   *  session-only kinds); it lets the anti-wipe guard tell a legitimate
   *  all-session-only emptying (liveTabCount > 0) from a transient truly-empty
   *  state (liveTabCount 0). */
  saveWorkspaceTabs: (
    id: string,
    tabs: SavedTab[],
    activeTabIndex: number,
    liveTabCount?: number,
  ) => void;
  /** Reorder via drag-and-drop: move `activeId` into `overId`'s slot. */
  reorderWorkspaces: (activeId: string, overId: string) => void;
};

/**
 * The workspace file, with crash recovery in front of it.
 *
 * Module scope rather than inside the `create` closure so the recovery notice
 * this store produces has a caller: `app/hooks/useStoreRecoveryNotices.ts` asks
 * for it at launch, the way it does for hosts, vault and forwards.
 */
const io = createTauriWorkspacesStoreIo();

/** Run the recovery pass and hand back what the user should be told, once. */
export function ensureLoaded(): Promise<StoreRecovery | null> {
  return io.ensureLoaded();
}
/** Drain the notice slot again, for a note that lands after startup. */
export function takeRecoveryNotice(): StoreRecovery | null {
  return io.takeRecoveryNotice();
}
/** Another window committed the workspace file. */
export function onWorkspacesChanged(cb: () => void): Promise<() => void> {
  return io.onChanged(cb);
}

export const useWorkspacesStore = create<State & Actions>((set, get) => {
  /**
   * Write both keys and commit them together.
   *
   * The state is read INSIDE the queued operation, so two persists in flight
   * both write the state as it is when their turn comes rather than the state
   * their caller happened to see.
   */
  const persist = (): Promise<void> =>
    io.enqueueWrite(async () => {
      const { workspaces, activeId } = get();
      await io.set(KEY_LIST, workspaces);
      await io.set(KEY_ACTIVE, activeId);
      await io.commit();
    });

  return {
    hydrated: false,
    workspaces: [],
    activeId: null,

    flush: () => persist(),

    async hydrate() {
      let list: Workspace[] = [];
      let active: string | null = null;
      let readFailed = false;

      // The anti-blank guard, asked of the layer that can actually answer it.
      //
      // This used to be three attempts with a backoff around a `get` that THREW
      // on a bad read; the recovered-store port never throws for a file it could
      // not use - `StoreFileIo.read` reports `missing` instead - so a loop
      // catching a throw would be dead code and the guard under it would be
      // permanently off. The recovery pass has already looked at the primary and
      // the snapshot by the time `fileState` resolves, so its verdict is the
      // question: anything but a good file, a first run, or a file the snapshot
      // put back means DO NOT write a default over what is there.
      //
      // `fileState` and not `ensureLoaded`, deliberately: `ensureLoaded` DRAINS
      // the notice, and the launch toast is the thing entitled to drain it. A
      // guard that competed for it would silence a recovery toast about half the
      // time, depending on which effect ran first.
      //
      // `hydrated` MUST still flip true in every branch below - the `tervia .`
      // CLI drain and other consumers gate on it, so a read failure that left it
      // false would strand them rather than merely lose the saved workspaces.
      const state = await io
        .fileState()
        .catch(() => ({ found: "unreachable" as const, recovered: false }));
      if (state.found !== "ok" && state.found !== "missing" && !state.recovered) readFailed = true;

      try {
        list = (await io.get<Workspace[]>(KEY_LIST)) ?? [];
        active = (await io.get<string | null>(KEY_ACTIVE)) ?? null;
      } catch {
        // The data directory itself is unreachable. Nothing was read, so nothing
        // may be written over.
        readFailed = true;
        list = [];
        active = null;
      }
      // Seed a default workspace on first run (or after a read failure).
      if (list.length === 0) {
        const ws: Workspace = {
          id: newWorkspaceId(),
          name: "Workspace 1",
          tabs: [],
          activeTabIndex: 0,
        };
        set({ workspaces: [ws], activeId: ws.id, hydrated: true });
        // Only overwrite the on-disk file on a GENUINE first run - one where
        // there was no usable file and no usable snapshot, and the empty list is
        // the truth. When the recovery pass reported anything else (a torn
        // primary its snapshot could not replace, a data directory that will not
        // resolve) do NOT persist the empty default over it: that would blank a
        // user's saved workspaces permanently, on one bad read. Leaving the file
        // untouched lets the next healthy launch recover it; the first real
        // change re-persists.
        if (!readFailed) {
          try {
            await persist();
          } catch {
            // Best-effort persist; the in-memory default is enough to boot.
          }
        }
        return;
      }
      set({
        workspaces: list,
        activeId: active ?? list[0]?.id ?? null,
        hydrated: true,
      });
    },

    setWorkspaces(workspaces) {
      set({ workspaces });
      void persist();
    },

    setActiveId(activeId) {
      set({ activeId });
      void persist();
    },

    createWorkspace(name) {
      const ws: Workspace = {
        id: newWorkspaceId(),
        name,
        tabs: [],
        activeTabIndex: 0,
      };
      set({ workspaces: [...get().workspaces, ws] });
      void persist();
      return ws;
    },

    renameWorkspace(id, name) {
      set({
        workspaces: get().workspaces.map((w) => (w.id === id ? { ...w, name } : w)),
      });
      void persist();
    },

    removeWorkspace(id) {
      const before = get();
      const removedIdx = before.workspaces.findIndex((w) => w.id === id);
      const next = before.workspaces.filter((w) => w.id !== id);
      // Always keep at least one workspace. Collapse to a default on last-delete.
      if (next.length === 0) {
        const ws: Workspace = {
          id: newWorkspaceId(),
          name: "Workspace 1",
          tabs: [],
          activeTabIndex: 0,
        };
        set({ workspaces: [ws], activeId: ws.id });
      } else {
        // Closing the active workspace hands focus to a neighbor (below if available, else above).
        const neighborIdx = removedIdx >= next.length ? next.length - 1 : removedIdx;
        const newActive = before.activeId === id ? next[neighborIdx].id : before.activeId;
        set({ workspaces: next, activeId: newActive });
      }
      void persist();
    },

    saveWorkspaceTabs(id, tabs, activeTabIndex, liveTabCount) {
      let changed = false;
      set({
        workspaces: get().workspaces.map((w) => {
          if (w.id !== id) return w;
          // Anti-wipe safety net: refuse an EMPTY snapshot over a workspace that
          // already has saved panes ONLY when the LIVE tabs were also empty
          // (liveTabCount 0) - a transient/error state (an exit cascade, a
          // mid-restore render, a switch flicker), never a real user action
          // since closeTab always keeps >=1 tab. When liveTabCount > 0 the
          // serialize is empty only because every remaining tab is session-only
          // (ai-diff/scm/ext) - a legitimate "closed all panes", so persist it
          // (else a deliberately closed pane revives on the next launch).
          if (tabs.length === 0 && w.tabs.length > 0 && (liveTabCount ?? 0) === 0) return w;
          changed = true;
          return { ...w, tabs, activeTabIndex };
        }),
      });
      if (changed) void persist();
    },

    reorderWorkspaces(activeId, overId) {
      if (activeId === overId) return;
      const list = get().workspaces;
      const from = list.findIndex((w) => w.id === activeId);
      const to = list.findIndex((w) => w.id === overId);
      if (from < 0 || to < 0 || from === to) return;
      // arrayMove: pull `from` out, splice it back in at `to`.
      const next = list.slice();
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
      set({ workspaces: next });
      void persist();
    },
  };
});

export function newWorkspaceId(): string {
  return `ws-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}
