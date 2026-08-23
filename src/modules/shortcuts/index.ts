export {
  isTerminalControlChord,
  isTerminalMetaChord,
  parseKeybindingString,
  SHORTCUTS,
  SHORTCUT_GROUPS,
  type KeyBinding,
  type Shortcut,
  type ShortcutGroup,
  type ShortcutId,
} from "./shortcuts";
export { useGlobalShortcuts, type ShortcutHandlers } from "./lib/useGlobalShortcuts";
export { runCommand, hasCommand } from "./lib/commandRegistry";
