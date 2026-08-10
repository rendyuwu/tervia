import { useEffect } from "react";

/**
 * Housekeeping for the right column's docked panels.
 *
 * There is no mutual exclusion any more: the column stacks its surfaces (see
 * `AppRightSlot`). What remains is closing a docked panel when the preference
 * that put it there flips off, which nothing else watches.
 */
export function useRightPanelExclusion(
  sshRightOpen: boolean,
  sshInRightPanel: boolean,
  hasAnySshLeaf: boolean,
  closeSshRight: () => void,
): void {
  // Close the SSH right panel when it's un-docked from the right or the last
  // SSH leaf disconnects (the sidebar hides SSH the same way, on !hasAnySshLeaf).
  useEffect(() => {
    if ((!sshInRightPanel || !hasAnySshLeaf) && sshRightOpen) {
      closeSshRight();
    }
  }, [sshInRightPanel, hasAnySshLeaf, sshRightOpen, closeSshRight]);
}
