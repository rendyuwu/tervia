import { useEffect, useRef } from "react";
import { usePreferencesStore } from "@/modules/settings/preferences";
import { SHORTCUTS, matchBinding, type ShortcutId } from "../shortcuts";
import { registerCommand, unregisterCommand } from "./commandRegistry";
import { COMMAND_PALETTE_MODAL, isModalOpen, isTopModal } from "./modalRegistry";

export type ShortcutHandler = (e: KeyboardEvent) => void;
export type ShortcutHandlers = Partial<Record<ShortcutId, ShortcutHandler>>;

/**
 * The one exemption from the modal gate below: the Command Palette's own
 * toggle chord. `CommandDialog` is built on the shared `Dialog` primitive, so
 * once the palette is open it registers as an open modal like any other -
 * which means the very chord that opened it would otherwise be swallowed by
 * its own gate, and Mod+Shift+P could open the palette but never close it
 * (Escape and outside-click still could, so this was never a stranding bug,
 * just a toggle that stopped toggling).
 *
 * THE EXEMPTION IS ON THE TARGET, NOT ON THE CHORD. Keyed by id
 * alone it read "this chord is always allowed through", and the justification
 * offered for that - the handler is `setCommandPaletteOpen(prev => !prev)` and
 * touches no other dialog's state - is true of the palette CLOSING ITSELF and
 * false of it OPENING over something else: with the host editor up,
 * Mod+Shift+P put the palette on top of a form the user was mid-edit in, which
 * is the modal-stacking version of exactly what the gate forbids. So the value
 * here is the modal the chord may act on, and the gate asks whether that modal
 * is the one currently on TOP of the stack. Palette on top -> the chord can
 * only be closing it -> let it through. Anything else on top - the host editor,
 * or a confirm stacked over the palette itself - -> suppressed like every other
 * chord.
 *
 * Keep this map to exactly this one entry. Anything added here must have the
 * same shape - a pure open/closed toggle of its OWN named dialog's visibility
 * and nothing more - never a chord whose handler touches tab/pane/editor/
 * session state, which is exactly the class of chord the gate exists to keep
 * out.
 * `tab.newEditor` and `tab.newAgent` open dialogs too, but with `set(true)`,
 * not a toggle, so they have no closing half to exempt and stay fully gated.
 */
const MODAL_GATE_EXEMPT: ReadonlyMap<ShortcutId, string> = new Map([
  ["commandPalette.open", COMMAND_PALETTE_MODAL],
]);

export type UseGlobalShortcutsOptions = {
  isDisabled?: (id: ShortcutId, e: KeyboardEvent) => boolean;
};

export function useGlobalShortcuts(
  handlers: ShortcutHandlers,
  options?: UseGlobalShortcutsOptions,
) {
  const latest = useRef({ handlers, options });
  latest.current = { handlers, options };

  // Access the shortcuts from the store
  const userShortcuts = usePreferencesStore((s) => s.shortcuts);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // No catalogued chord fires while a Dialog/AlertDialog is open -
      // a background action (Ctrl+W closing the tab, say) must not run out
      // from under a modal the user is mid-edit in. Three things are
      // deliberately unaffected: Escape, because it is not in SHORTCUTS (see
      // shortcuts.ts) so this loop never matches it and Radix's own
      // Escape-to-close on the dialog keeps handling it; typing/select-
      // all/copy/paste/undo inside the dialog's own inputs, because those are
      // native browser behavior on the focused element, not a chord this
      // catalog defines - returning here (no preventDefault) lets the
      // keystroke fall through to the input untouched either way; and the ids
      // in MODAL_GATE_EXEMPT above, checked per-match below rather than as an
      // early return here, because the gate now has to know WHICH chord
      // matched before it can decide whether to apply.
      const { handlers, options } = latest.current;
      for (const s of SHORTCUTS) {
        // Use user-defined bindings if they exist, otherwise use default
        const bindings = userShortcuts[s.id] || s.defaultBindings;

        const isMatch = bindings.some((b) => matchBinding(e, b, s.id));
        if (!isMatch) continue;

        // The modal the matched chord is allowed to act on, if any. Undefined
        // for every chord but one; `isTopModal` then decides whether that one
        // modal is the one the user is actually looking at.
        const mayActOn = MODAL_GATE_EXEMPT.get(s.id);
        if (isModalOpen() && (mayActOn === undefined || !isTopModal(mayActOn))) return;
        if (options?.isDisabled?.(s.id, e)) return;
        const h = handlers[s.id];
        if (!h) return;
        e.preventDefault();
        e.stopImmediatePropagation();
        h(e);
        return;
      }
    };
    window.addEventListener("keydown", onKey, { capture: true });
    return () => window.removeEventListener("keydown", onKey, { capture: true });
  }, [userShortcuts]);

  // Publish this caller's commands to the shared registry so the Command Palette
  // can run them directly (see commandRegistry). The id set is stable per caller
  // even though the handler closures are recreated each render, so key off the
  // id signature and have each registered invoker read `latest` to always call
  // the freshest closure.
  const idSig = Object.keys(handlers).sort().join(",");
  useEffect(() => {
    const ids = Object.keys(latest.current.handlers) as ShortcutId[];
    const invokers = new Map<ShortcutId, ShortcutHandler>();
    for (const id of ids) {
      const invoke: ShortcutHandler = (e) => latest.current.handlers[id]?.(e);
      invokers.set(id, invoke);
      registerCommand(id, invoke);
    }
    return () => {
      for (const [id, invoke] of invokers) unregisterCommand(id, invoke);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [idSig]);
}
