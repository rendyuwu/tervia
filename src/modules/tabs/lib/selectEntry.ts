/**
 * The three routes a tab-strip chip has into "activate this entry" - Radix's
 * `onValueChange`, the chip's own click, and a leaf drag starting - and the
 * one expression they share.
 *
 * A LEAF module on purpose: the only import is `import type { Entry }`, which is
 * erased, so `scripts/rail-views-verify.ts` can import this at runtime under
 * `tsx` and EXECUTE the click route instead of pinning a substring of it - pin
 * the expression, not the name. A value import would drag
 * `entries.ts` in, and through it the `@/`-aliased modules that a script with no
 * bundler cannot resolve. Keep it that way.
 */
import type { Entry } from "./entries";

/**
 * The tab-strip chip's own click route into "activate this entry".
 *
 * Named once here rather than re-spelled at every hop: `TabBar`,
 * `SortableTabGroup` and `renderEntryBody` all thread the same callback down and
 * all three name it by THIS type, so a chip wired to a subtly different signature
 * is a compile error rather than a click that goes somewhere else.
 *
 * `Header` holds a fourth copy, still hand-written, and it stays that way for now:
 * it is outside this module, so pulling it in would make the header import from
 * `tabs/lib`. Stated rather than left to be discovered - the reuse is real up to
 * the module boundary and stops there.
 */
export type SelectEntry = (tabId: number, leafId: number) => void;

/**
 * The trigger's OWN click route, as props to spread onto it.
 *
 * With a rail view (Vault, Port Forwarding) covering the tab area, the
 * strip stays on screen but `activeKey` still names the tab underneath it - so
 * clicking that tab's own chip is not a value CHANGE, and the controlled Radix
 * `Tabs` in `TabBar` never calls `onValueChange`. The click that most plainly
 * means "show me that tab again" was the one click the strip ignored: the user
 * had to click some OTHER chip first, and only then could they click back.
 *
 * The suppression is NOT in the trigger, which is where this comment used to
 * point. `TabsTrigger`'s `onMouseDown` and `onKeyDown` both call
 * `context.onValueChange(value)` with no test against the current value; only
 * `onFocus` checks `!isSelected`. It is one layer down, in
 * `@radix-ui/react-use-controllable-state`'s `setValue`: while controlled, it
 * calls `onChangeRef.current?.(value2)` only `if (value2 !== prop)`. Located
 * exactly, because a reader who opens `react-tabs` to check the old claim finds
 * the opposite and concludes the whole paragraph is wrong.
 *
 * So this is deliberately UNCONDITIONAL in the entry's key. It fires on every
 * click and hands the pair straight to `onSelectEntry`, whose funnel
 * (`tabView.ts`'s `focusTabView`) is already unconditional in the id for exactly
 * this reason and collapses the genuinely redundant case into the same object.
 *
 * REJECTED: threading `railView` down into `Header`/`TabBar` and passing
 * `value={railView === null ? (activeKey ?? "") : ""}` so that Radix sees a
 * change. That changes what the strip LOOKS like (the covered tab loses its
 * active styling, and Radix's roving tabindex moves with it) in order to fix
 * what a click DOES. The accepted cost of the route taken instead is the
 * mirror image: a covered tab's chip keeps its active styling and its accent
 * stripe, both painted from the separate `e.key === activeKey` comparison in
 * `renderEntryBody`. The click was the complaint, not the highlight.
 *
 * A drag needs no guard in here, and adding one would be dead code: dnd-kit's
 * `PointerSensor.handleStart` registers a capture-phase `click` listener on
 * `document` that `stopPropagation()`s once the 5px activation constraint is
 * met, and removes it 50ms after detach. React 19 attaches its listeners to the
 * app root, a descendant of `document`, so the click that ends a real drag never
 * reaches this handler. A sub-5px "drag" never activates the sensor and IS a
 * click, which is what should navigate.
 */
export function entrySelectHandlers(
  entry: Entry,
  onSelectEntry: SelectEntry,
): { onClick: () => void } {
  return {
    onClick: () => onSelectEntry(entry.tabId, entry.leafId),
  };
}

/**
 * The drag counterpart of `entrySelectHandlers`, for the same Radix reason: the
 * dragged chip's mousedown is a no-op when the chip is already the active
 * entry, which under a rail view is the covered tab. So a leaf drag started
 * there reached the drop with the view still up, and closed the view only if
 * the drop reached `reorderLeafInGroup`. Selecting at activation makes a header
 * rearrangement leave the view before the drop, the same way "Toggle Split
 * Orientation" does. With no view, or on a chip that is not active, it is a
 * no-op repeat of what mousedown already did (`focusTabView` and `focusPane`
 * both return `curr`).
 *
 * `tab:` group drags are excluded on purpose: they reorder the strip, which a
 * view does not cover. The same asymmetry remains there and is accepted: a
 * single-leaf tab's chip carries the group listeners (`SortableTabGroup.tsx`,
 * `isGroupDragHandle`), so dragging the covered tab's chip keeps the view up,
 * while dragging any other chip leaves it on mousedown. An unknown leaf id
 * does nothing.
 */
export function selectDraggedLeaf(
  activeDragId: string,
  entries: readonly Entry[],
  onSelectEntry: SelectEntry,
): void {
  if (!activeDragId.startsWith("leaf:")) return;
  const leafId = Number(activeDragId.slice("leaf:".length));
  const entry = entries.find((e) => e.leafId === leafId);
  if (entry) onSelectEntry(entry.tabId, entry.leafId);
}
