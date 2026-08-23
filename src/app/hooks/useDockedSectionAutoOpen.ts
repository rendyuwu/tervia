import { useEffect, useMemo, useRef } from "react";

import {
  isRightSectionOpen,
  MOVABLE_SECTIONS,
  useRightColumnStore,
  useSidebarPlacementStore,
  type RightSectionId,
} from "@/modules/rightPanel";

/**
 * Restore right-docked sidebar sections' open/closed state across launches.
 *
 * A movable section docked to the right (placement === "right") should come
 * back the way the user left it - open if they had it open, closed if they
 * closed it - not reopen on every launch. The right column's live state is
 * session-only, so each section's last intent is persisted in
 * `useSidebarPlacementStore.rightOpen` and applied here:
 *
 *   - On the first mount where a docked section exists, open every one whose
 *     persisted intent isn't `false`. The column stacks them, so they no longer
 *     compete for a single slot; a section the user closed stays closed and its
 *     status-bar icon still reopens it.
 *   - Afterwards, mirror each section's live open/closed state back into the
 *     persisted intent, so the next launch restores the latest state.
 *
 * Without the persisted intent a docked section reopened on every launch even
 * after the user closed it (the reported "DB panel always opens on startup").
 */
export function useDockedSectionAutoOpen(): void {
  const placement = useSidebarPlacementStore((s) => s.placement);
  const open = useRightColumnStore((s) => s.open);
  const decided = useRef(false);

  const docked = useMemo<RightSectionId[]>(
    () => MOVABLE_SECTIONS.filter((s) => placement[s.id] === "right").map((s) => s.id),
    [placement],
  );

  // One-shot restore on the first mount where a docked section exists.
  useEffect(() => {
    if (decided.current) return;
    if (docked.length === 0) return; // none docked
    decided.current = true;
    const { rightOpen } = useSidebarPlacementStore.getState();
    for (const id of docked) {
      // Respect the persisted last state: a section the user closed stays closed.
      if (rightOpen[id] === false) continue;
      useRightColumnStore.getState().openSection(id);
    }
  }, [docked]);

  // After the restore decision, mirror each docked section's live open/closed
  // state into the persisted intent so the next launch comes back the same way.
  useEffect(() => {
    if (!decided.current) return;
    const store = useSidebarPlacementStore.getState();
    for (const id of docked) {
      store.setRightOpen(id, isRightSectionOpen(open, id));
    }
  }, [open, docked]);
}
