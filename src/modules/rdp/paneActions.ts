/**
 * Leaf-addressed actions the PANE HEADER fires at an RDP pane body.
 *
 * The header lives in `PaneTreeView` and the session lives inside `RdpPane`, so
 * the button and the thing it acts on are in different components with no
 * common owner. A window event keyed by leaf id is how the removed browser pane
 * solved the same problem (its address-bar focus), and it is the cheap answer
 * here too: no handle registry to keep in sync with mount order, and no new
 * prop threaded through `PaneStack` -> `PaneTreeView` -> `LeafBundle` for one
 * button.
 *
 * Only actions the header owns belong here. Everything the pane can do to
 * itself (reconnect from its own error overlay) stays local state.
 */

/**
 * Actions a header button can fire. A union of one today, and still a union:
 * the subscriber dispatches through a `Record<RdpPaneAction, ...>`, so adding a
 * member is a compile error there rather than an event that arrives and is
 * silently ignored.
 *
 * Reconnecting is deliberately NOT here. The pane's own error overlay owns that
 * button, because it is only meaningful when the session is already down - and
 * that is exactly when the overlay is the thing on screen.
 */
export type RdpPaneAction =
  /** Send the Ctrl+Alt+Del chord. The webview never sees the real one: on
   *  Windows it is a Secure Attention Sequence the OS consumes first. */
  "ctrlAltDel";

const EVENT = "tervia://rdp-pane-action";

type Detail = { leafId: number; action: RdpPaneAction };

export function fireRdpPaneAction(leafId: number, action: RdpPaneAction): void {
  window.dispatchEvent(new CustomEvent<Detail>(EVENT, { detail: { leafId, action } }));
}

/** Listen for actions aimed at ONE leaf. Returns the unsubscribe. */
export function onRdpPaneAction(leafId: number, run: (action: RdpPaneAction) => void): () => void {
  const handler = (e: Event) => {
    const detail = (e as CustomEvent<Detail>).detail;
    if (detail?.leafId === leafId) run(detail.action);
  };
  window.addEventListener(EVENT, handler);
  return () => window.removeEventListener(EVENT, handler);
}
