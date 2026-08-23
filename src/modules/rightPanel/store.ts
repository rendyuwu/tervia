/**
 * Right-column store. Tracks which docked sidebar sections are showing in the
 * right column.
 *
 * `open` is a LIST, not a single target: the right column stacks its surfaces
 * the same way the left sidebar does, so more than one can be open at once.
 * Test membership with `isRightSectionOpen` rather than looking at one entry.
 *
 * Not persisted — the column's live state is session-only; what a docked section
 * restores across launches lives in `useSidebarPlacementStore.rightOpen`.
 */
import { create } from "zustand";

import type { RightSectionId } from "./placement";

type State = {
  /** Open sections, in the order they were opened. The visual order is the
   *  section stack's business (it persists its own drag order). */
  open: RightSectionId[];
};

type Actions = {
  openSection: (id: RightSectionId) => void;
  closeSection: (id: RightSectionId) => void;
  toggleSection: (id: RightSectionId) => void;
};

/** Whether a section is currently in the right column. Takes the list so a
 *  component can select `open` once and test several ids against it. */
export function isRightSectionOpen(open: readonly RightSectionId[], id: RightSectionId): boolean {
  return open.includes(id);
}

export const useRightColumnStore = create<State & Actions>((set, get) => ({
  open: [],
  openSection: (id) => {
    const { open } = get();
    if (open.includes(id)) return;
    set({ open: [...open, id] });
  },
  closeSection: (id) => {
    const { open } = get();
    if (!open.includes(id)) return;
    set({ open: open.filter((o) => o !== id) });
  },
  toggleSection: (id) => {
    if (get().open.includes(id)) get().closeSection(id);
    else get().openSection(id);
  },
}));
