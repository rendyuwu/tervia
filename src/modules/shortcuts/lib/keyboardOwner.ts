/**
 * WHO OWNS THE RAW KEYBOARD RIGHT NOW - the question `yieldsToRawKeyboard`
 * below actually needs answered.
 *
 * A focused terminal owns every bare-Ctrl control code (Ctrl+E, Ctrl+W, Ctrl+K,
 * Ctrl+L, Ctrl+[ Esc, Ctrl+I Tab, the tmux/screen prefix - except where the
 * bound action is in `FIRES_OVER_RAW_KEYBOARD`) and every bare-Alt
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

import { isTerminalControlChord, isTerminalMetaChord, type ShortcutId } from "../shortcuts";

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

/**
 * The actions that fire over a focused terminal or RDP pane even though their
 * chord is a control code that surface would otherwise take: `pane.splitRight`
 * (^D EOF), `pane.focusNext` (^] GS), `pane.focusPrev` (^[ Esc). The pane pair
 * qualifies because it moves focus and mutates nothing - navigation, not
 * mutation.
 *
 * Scope comes from the modal stack, not from this table - the issue that asked
 * for the pair said "scope the exemption by the target's position in the modal
 * stack, not by the chord's identity":
 *  - This table decides WHICH ids fire over a raw-keyboard surface.
 *  - The modal stack decides WHERE. `useGlobalShortcuts`' modal gate returns
 *    for all of these ids whenever any modal is on the stack, the Command
 *    Palette included, because none of them has a `MODAL_GATE_EXEMPT` entry.
 *    The order of the two checks does not matter; both are side-effect-free
 *    early returns.
 *  - Raw-keyboard surfaces exist only inside `PaneTreeView`, so the exemption
 *    can only apply while the tab area is the top layer.
 *  - Never add these ids to `MODAL_GATE_EXEMPT`.
 *
 * Keyed on the action, not the key: a user who rebinds one of these ids
 * carries the exemption to the new chord, and any other action bound to
 * Ctrl+] / Ctrl+[ still yields. Add a member only if its handler acts on the
 * tab area's panes.
 */
const FIRES_OVER_RAW_KEYBOARD: Partial<Record<ShortcutId, true>> = {
  "pane.splitRight": true,
  "pane.focusNext": true,
  "pane.focusPrev": true,
};

/**
 * True when the keydown for shortcut `id` must be let through to the raw
 * surface instead of firing the app action bound to it. Applied by
 * `useGlobalShortcuts` to every caller's matched chord.
 *
 * A focused terminal owns every bare-Ctrl control code (Ctrl+E, Ctrl+W,
 * Ctrl+K, Ctrl+L, Ctrl+[ Esc, Ctrl+I Tab, the tmux/screen prefix, … - except
 * where the bound action is in `FIRES_OVER_RAW_KEYBOARD`) and
 * every bare-Alt meta sequence (readline M-b / M-f / M-d / M-1..9). On
 * Win/Linux `Mod` is Ctrl, so those chords would otherwise fire an app
 * action (close tab, word-wrap, explorer search, …) and the byte never
 * reaches the shell. Exception: the actions in `FIRES_OVER_RAW_KEYBOARD`
 * (`pane.splitRight` Ctrl+D, `pane.focusNext` Ctrl+], `pane.focusPrev`
 * Ctrl+[) always fire; `pane.splitDown` already passes because it carries
 * Shift. Terminal-safe app chords keep Shift/Meta or add a second modifier
 * (Ctrl+Shift+C copy, Ctrl+Shift+X close, Ctrl+Alt+P, Shift+Alt+F) and stay
 * active; Ctrl+Tab / Ctrl+digit / zoom are not control codes either.
 *
 * A focused RDP pane is gated the same way and for the same reason: the
 * remote desktop owns its own Ctrl and Alt chords, so Ctrl+W has to reach
 * Windows rather than close the pane showing it. (Ctrl+Alt+Del is the one
 * chord no gate can deliver - the OS eats it - which is why the pane header
 * has a button for it.)
 *
 * `tabAreaCovered` is the rail-view case, made explicit rather than trusted
 * to the browser blurring what it hides: a covered surface does not own the
 * keyboard by definition, and making that a state question the caller
 * answers - not a focus question this function tries to infer - keeps it
 * from depending on whether Chromium happens to move focus off a
 * `visibility: hidden` subtree.
 */
export function yieldsToRawKeyboard(
  id: ShortcutId,
  target: FocusTarget,
  e: KeyboardEvent,
  tabAreaCovered: boolean,
): boolean {
  return (
    FIRES_OVER_RAW_KEYBOARD[id] !== true &&
    !tabAreaCovered &&
    ownsRawKeyboard(target) &&
    (isTerminalControlChord(e) || isTerminalMetaChord(e))
  );
}
