import { type RailViewKind } from "./pages";

/**
 * WHAT THE WORKSPACE AREA IS SHOWING: the active tab, plus the rail view
 * covering it (DCR-1) when there is one.
 *
 * ONE state object rather than two `useState`s, because the pair carries an
 * invariant that two independent setters cannot express: **a tab cannot become
 * active while a view is still covering it.** Held as separate state, `railView`
 * had ten routes into the tab area that each had to remember to clear it, and
 * nine of them did not - Ctrl+T, Ctrl+Tab, Ctrl+1..9, header quick-connect, a
 * file click, a workspace switch, an OSC-8889 open. Each looked like it had done
 * nothing, because the view was still on top of the tab it had just activated.
 *
 * So the rule lives at the state write instead: every route into the tab area
 * goes through {@link focusTabView}, and leaving the view is not something a
 * caller can forget. `useTabs` holds this object; nothing else may write it.
 *
 * Pure functions, exported, so `scripts/rail-views-verify.ts` can EXECUTE the
 * rule: the hook that holds the state needs a React renderer, the rule does not.
 *
 * `railView` is deliberately not persisted (it is not in `SavedTab`): a relaunch
 * comes up on the tabs, because what a workspace is for is the connections in it
 * and a saved detour into the vault would be the first thing every launch shows.
 */
export type TabView = {
  /**
   * The active tab's id, or 0 for "nothing is active" - the mount state, before
   * workspace restore has populated the tab list, and what an emptied tab list
   * would leave behind.
   */
  activeId: number;
  /** The rail view covering the tab area, or null when the tabs are showing. */
  railView: RailViewKind | null;
};

/** Mount state: no tab active, no view covering it. */
export const INITIAL_TAB_VIEW: TabView = { activeId: 0, railView: null };

/**
 * Focus tab `id` AND leave whatever rail view was covering it. The single write
 * every route into the tab area funnels through - a chord, a tab click, a minted
 * tab, a workspace restore.
 *
 * Deliberately unconditional in `id`: clearing only when the id CHANGES is the
 * subtle version of the same bug, because Ctrl+1 on the tab that is already
 * active is exactly the case where the user is asking to be shown a tab the
 * Vault is covering. "The id did not change" must not mean "do nothing".
 */
export function focusTabView(curr: TabView, id: number): TabView {
  if (curr.activeId === id && curr.railView === null) return curr;
  return { activeId: id, railView: null };
}

/**
 * Re-home `activeId` after the entry holding it was REMOVED. Not a route into
 * the tab area, so it deliberately leaves `railView` alone: closing a tab in the
 * strip (which stays visible above a rail view) while the Vault is up must not
 * throw the user out of the Vault they are reading.
 *
 * The two close paths in `useTabs` are its only callers, and they reach it by
 * name - the distinction is stated rather than encoded in the shape of the
 * argument, which is what let a removal masquerade as a focus before.
 */
export function rehomeTabView(curr: TabView, id: number): TabView {
  if (curr.activeId === id) return curr;
  return { ...curr, activeId: id };
}

/** Show the tabs, whatever view was covering them, without touching focus. */
export function showTabsIn(curr: TabView): TabView {
  return curr.railView === null ? curr : { ...curr, railView: null };
}

/**
 * The rail button, both ways: clicking the lit one goes back to the tabs, so the
 * rail never holds a pressed state with no way out of it.
 */
export function toggleRailViewIn(curr: TabView, view: RailViewKind): TabView {
  return { ...curr, railView: curr.railView === view ? null : view };
}
