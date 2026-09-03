/**
 * The two routes a tab-strip chip has into "activate this entry", and the one
 * expression they share.
 *
 * A LEAF module on purpose: the only import is `import type { Entry }`, which is
 * erased, so `scripts/rail-views-verify.ts` can import this at runtime under
 * `tsx` and EXECUTE the click route instead of pinning a substring of it (§5
 * decision 17: pin the expression, not the name). A value import would drag
 * `entries.ts` in, and through it the `@/`-aliased modules that a script with no
 * bundler cannot resolve. Keep it that way.
 */
import type { Entry } from "./entries";

/**
 * Activate a tab-strip entry. `leafId` is null for a standalone tab.
 *
 * Named once here rather than re-spelled at every hop: `TabBar`,
 * `SortableTabGroup` and `renderEntryBody` all thread the same callback down, and
 * a chip wired to a subtly different signature is then a compile error rather
 * than a click that goes somewhere else.
 */
export type SelectEntry = (tabId: number, leafId: number | null) => void;

/**
 * The `(tabId, leafId)` pair an entry selects. ONE expression, used by BOTH
 * routes below.
 *
 * `entry.kind === "pane-leaf" ? entry.leafId : null` was written out by hand at
 * each call site, which is exactly what let them drift - and the click route is
 * new, so leaving it hand-written would have added a second place to get a
 * standalone tab's `null` wrong.
 */
export function entrySelectTarget(entry: Entry): { tabId: number; leafId: number | null } {
  return { tabId: entry.tabId, leafId: entry.kind === "pane-leaf" ? entry.leafId : null };
}

/**
 * The trigger's OWN click route, as props to spread onto it.
 *
 * D-NAV1: with a rail view (Vault, Port Forwarding) covering the tab area, the
 * strip stays on screen but `activeKey` still names the tab underneath it - so
 * clicking that tab's own chip is not a value CHANGE, and the controlled Radix
 * `Tabs` in `TabBar` never calls `onValueChange` (each of its trigger's
 * activation handlers is guarded by `value !== context.value`). The click that
 * most plainly means "show me that tab again" was the one click the strip
 * ignored: the user had to click some OTHER chip first, and only then could they
 * click back.
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
    onClick: () => {
      const { tabId, leafId } = entrySelectTarget(entry);
      onSelectEntry(tabId, leafId);
    },
  };
}
