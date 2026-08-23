/**
 * Public barrel for the right column: which sidebar sections are docked there
 * and which of them are open. Import from `@/modules/rightPanel`; internals may
 * move.
 */

export {
  MOVABLE_SECTIONS,
  isMovableSection,
  useSidebarPlacementStore,
  type RightSectionId,
} from "./placement";
export { isRightSectionOpen, useRightColumnStore } from "./store";
export { RightSectionToggles } from "./RightSectionToggles";
