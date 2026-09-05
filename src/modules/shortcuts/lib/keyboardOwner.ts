/**
 * WHO OWNS THE RAW KEYBOARD RIGHT NOW - the question App's `isDisabled` gate
 * actually needs answered.
 *
 * A focused terminal owns every bare-Ctrl control code (Ctrl+E, Ctrl+W, Ctrl+K,
 * Ctrl+L, Ctrl+[ Esc, Ctrl+I Tab, the tmux/screen prefix) and every bare-Alt
 * meta sequence, and a focused RDP pane owns the same chords for the same
 * reason - so those keystrokes must fall through to the surface instead of
 * firing an app action. That is a claim about FOCUS.
 *
 * It used to be answered with `activeLeafKind(activeTab) === "terminal"`, which
 * is a claim about which leaf is ACTIVE IN THE TAB - a different thing, and
 * wrong in both directions:
 *
 *  - Click the tab strip, the sidebar or a rail view and the terminal is no
 *    longer holding the caret, but the active leaf has not changed - so Ctrl+W
 *    stayed suppressed and closed no tab anywhere. A suppression that
 *    suppresses everywhere is indistinguishable from an unbound chord.
 *  - Open a rail view over the tab area and the terminal is invisible and
 *    `pointer-events-none`, yet still the active leaf - so Ctrl+T, Ctrl+] and
 *    Ctrl+[ were swallowed by a terminal nobody could see.
 *
 * So ask the DOM. Both surfaces already mark themselves for other features -
 * `data-terminal-leaf-id` on `TerminalPane`'s container (the file-drop
 * hit-test uses it) and `data-rdp-leaf-id` on `RdpPane`'s focusable host - and
 * the element that actually holds focus is inside one of them: xterm's
 * `.xterm-helper-textarea` for a terminal, the marked div itself for RDP.
 *
 * Split into a pure predicate over anything with `closest` plus a thin
 * event->target step, so `scripts/keybindings-terminal-verify.ts` can EXECUTE
 * the rule without a DOM: the predicate is the part that decides, and the part
 * that needs a browser is one line long.
 */

/** The least this needs from a DOM node: ask an ancestor-or-self question. */
export type FocusTarget = { closest(selectors: string): unknown } | null;

/**
 * The surfaces that own raw key input while focused. Every attribute named
 * here must be one a real pane renders - a selector that matches nothing would
 * turn the gate permanently OFF and let app chords eat the shell's control
 * codes, which is silent. `keybindings-terminal-verify.ts` reads the pane
 * sources back and fails if a marker named here is not on one of them.
 */
export const KEYBOARD_OWNING_SURFACES = "[data-terminal-leaf-id],[data-rdp-leaf-id]";

/**
 * True when `target` sits inside (or is) a surface that owns the raw keyboard.
 * `null` - nothing focused, or a keydown whose target is not an element - is
 * false: with no surface holding the keys, the app chord is what the keystroke
 * means.
 */
export function ownsRawKeyboard(target: FocusTarget): boolean {
  if (target === null) return false;
  return target.closest(KEYBOARD_OWNING_SURFACES) !== null;
}

/**
 * The element a keydown is being delivered to. `e.target` rather than
 * `document.activeElement` because it is the event's own answer and cannot be
 * stale; the fallback covers a synthesised event with no element target.
 */
export function focusTargetOf(e: KeyboardEvent): FocusTarget {
  if (e.target instanceof Element) return e.target;
  return document.activeElement;
}
