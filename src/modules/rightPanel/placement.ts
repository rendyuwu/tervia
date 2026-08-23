/**
 * Placement (left sidebar vs right column) for the sidebar sections that may be
 * docked, persisted to localStorage (the sidebar lives in the main window only).
 *
 * Live open/closed state for a right-placed section is session-only and lives in
 * `useRightColumnStore`. What IS persisted here (`rightOpen`) is the section's
 * last open/closed intent in the column, so a docked section restores that state
 * on the next launch instead of always auto-reopening — see
 * `useDockedSectionAutoOpen`.
 */
import { create } from "zustand";

const LS_KEY = "tedi:sidebar:placement";
const LS_OPEN_KEY = "tedi:sidebar:right-open";

/**
 * Sidebar sections the user can dock to the right column. `id` is both the
 * AppSidebar section key and the placement key.
 * Remote (`ssh`) is absent on purpose: it docks right through its own
 * `sshInRightPanel` preference and `sshRightPanelStore`.
 */
export const MOVABLE_SECTIONS = [
  { id: "files", title: "Files" },
  { id: "workspaces", title: "Workspaces" },
] as const;

export type RightSectionId = (typeof MOVABLE_SECTIONS)[number]["id"];

/** Whether an arbitrary section key names a section that may be docked right. */
export function isMovableSection(key: string): key is RightSectionId {
  return MOVABLE_SECTIONS.some((s) => s.id === key);
}

type Placement = "left" | "right";

type State = {
  placement: Record<string, Placement>;
  /** Per-section last open/closed intent while docked right. Absent = treat as
   *  open on first dock; `false` keeps the section closed across launches
   *  instead of auto-reopening. */
  rightOpen: Record<string, boolean>;
};

type Actions = {
  moveRight: (key: string) => void;
  moveLeft: (key: string) => void;
  /** Record the docked section's live open/closed state so the next launch
   *  restores it. Driven by `useDockedSectionAutoOpen`. */
  setRightOpen: (key: string, open: boolean) => void;
};

function load(): Record<string, Placement> {
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(LS_KEY) ?? "null");
    if (raw && typeof raw === "object") {
      const out: Record<string, Placement> = {};
      for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
        if (v === "right" || v === "left") out[k] = v;
      }
      return out;
    }
  } catch {
    // Corrupt value: default everything to the left sidebar.
  }
  return {};
}

function persist(placement: Record<string, Placement>): void {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(placement));
  } catch {
    // localStorage may be unavailable; placement is non-critical.
  }
}

function loadRightOpen(): Record<string, boolean> {
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(LS_OPEN_KEY) ?? "null");
    if (raw && typeof raw === "object") {
      const out: Record<string, boolean> = {};
      for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
        if (typeof v === "boolean") out[k] = v;
      }
      return out;
    }
  } catch {
    // Corrupt value: treat every docked section as default-open.
  }
  return {};
}

function persistRightOpen(rightOpen: Record<string, boolean>): void {
  try {
    localStorage.setItem(LS_OPEN_KEY, JSON.stringify(rightOpen));
  } catch {
    // localStorage may be unavailable; non-critical.
  }
}

export const useSidebarPlacementStore = create<State & Actions>((set, get) => ({
  placement: load(),
  rightOpen: loadRightOpen(),
  moveRight: (key) => {
    const next = { ...get().placement, [key]: "right" as Placement };
    persist(next);
    // Docking opens the section in the column, so its restored intent starts open.
    const nextOpen = { ...get().rightOpen, [key]: true };
    persistRightOpen(nextOpen);
    set({ placement: next, rightOpen: nextOpen });
  },
  moveLeft: (key) => {
    const next = { ...get().placement, [key]: "left" as Placement };
    persist(next);
    set({ placement: next });
  },
  setRightOpen: (key, open) => {
    if (get().rightOpen[key] === open) return;
    const next = { ...get().rightOpen, [key]: open };
    persistRightOpen(next);
    set({ rightOpen: next });
  },
}));
