import { useEffect, useRef } from "react";
import { usePreferencesStore } from "@/modules/settings/preferences";
import { SHORTCUTS, matchBinding, type ShortcutId } from "../shortcuts";
import { registerCommand, unregisterCommand } from "./commandRegistry";
import { isModalOpen } from "./modalRegistry";

export type ShortcutHandler = (e: KeyboardEvent) => void;
export type ShortcutHandlers = Partial<Record<ShortcutId, ShortcutHandler>>;

/**
 * VLT-30's one exemption from the modal gate below: the Command Palette's own
 * toggle chord. `CommandDialog` is built on the shared `Dialog` primitive, so
 * once the palette is open it registers as an open modal like any other -
 * which means the very chord that opened it would otherwise be swallowed by
 * its own gate, and Mod+Shift+P could open the palette but never close it
 * (Escape and outside-click still could, so this was never a stranding bug,
 * just a toggle that stopped toggling).
 *
 * Safe to exempt because `commandPalette.open`'s handler is
 * `setCommandPaletteOpen(prev => !prev)` and nothing else (see
 * `shortcutHandlers.ts`) - it only flips the palette's own visibility, the
 * same class of action Radix's Escape-to-close already reaches through a
 * modal untouched by this gate. It does not read or write any OTHER dialog's
 * state, so firing it while a *different* modal is open cannot do what
 * VLT-30 forbids: mutate app state the user can't see behind that modal.
 * `tab.newEditor` and `tab.newAgent` open dialogs too, but with `set(true)`,
 * not a toggle, so they have no closing half to exempt and stay fully gated.
 *
 * Keep this set to exactly this one id. Anything added here must have the
 * same shape - a pure open/closed toggle of its OWN dialog's visibility and
 * nothing more - never a chord whose handler touches tab/pane/editor/session
 * state, which is exactly the class of chord VLT-30 exists to keep out.
 */
const MODAL_GATE_EXEMPT: ReadonlySet<ShortcutId> = new Set(["commandPalette.open"]);

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
      // VLT-30: no catalogued chord fires while a Dialog/AlertDialog is open -
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

        if (isModalOpen() && !MODAL_GATE_EXEMPT.has(s.id)) return;
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
