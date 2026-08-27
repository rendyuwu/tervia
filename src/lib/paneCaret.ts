/**
 * Which pane owns the keyboard caret when the tabs change underneath it.
 *
 * VLT-39. The mechanism below was MEASURED in a headless Chromium against a
 * structural copy of this app's tab strip (Radix `Tabs` + panes that stay
 * mounted behind `visibility:hidden`/`display:none`), not reasoned about, after
 * two rounds of reasoning about it got the wrong answer:
 *
 *   - The tab strip is a Radix `Tabs` (`TabBar.tsx`), and Radix changes the
 *     selected value on MOUSEDOWN, not on click.
 *   - React 19 flushes that whole commit - layout effects AND passive effects -
 *     synchronously inside the same mousedown dispatch.
 *   - The browser then runs the DEFAULT ACTION of that mousedown, which is to
 *     focus the element that was clicked: the tab chip.
 *
 * Observed, in order, for one click on a tab chip:
 *
 *     mousedown (capture)        activeElement = the pane being left
 *     radix onValueChange        -> React renders and commits
 *     useLayoutEffect            terminal.focus()      <- lands
 *     useEffect                  searchInput.focus()   <- lands
 *     mousedown (bubble end)     activeElement = whichever of those ran last
 *     mousedown default action   activeElement = THE TAB CHIP
 *
 * Every focus a pane sets while reacting to "my tab just became visible" is
 * therefore overwritten a moment later, whichever pane set it and whichever
 * kind of effect it used. That is one defect with two faces: the Hosts search
 * box never got the caret on a click-through (R11.3/R11.5), and a terminal
 * sharing a split with Hosts never got it back after a tab round-trip
 * (R11.6). Nothing was stealing anything from anything - both panes lost to
 * the browser, and the caret ended up on the tab chip, where typing does
 * nothing.
 *
 * So "focus yourself when you become visible" cannot be the rule. The rule is:
 * a pane CLAIMS the caret, and the hand-over happens one animation frame later
 * - after the gesture that caused the switch has finished its own focus
 * handling, and still ~16ms before anyone can press a key.
 *
 * A deferred hand-over needs three guards, or it becomes a different bug. They
 * are `caretHandoff` below, kept as a pure function so the truth table is
 * checkable without a DOM (`scripts/pane-caret-verify.ts`), the same split
 * `focusRestore.ts` uses for the Alt-Tab policy next door.
 */

/**
 * The hand-over decision, made at FLUSH time (one frame after the claim), from
 * three facts about the world as it is then - never as it was when the claim
 * was made. A claim that was right when it was scheduled is routinely wrong by
 * the time it runs; that is the whole reason this is deferred.
 *
 * `stillOnScreen` - the claimant is still the visible tab's active leaf. This
 * is the guard that keeps a slow async attach (up to ~2s of waiting for a
 * container ref during a workspace restore, then a 250ms poll) from pulling the
 * caret out of whatever the user switched to in the meantime.
 *
 * `caretInsideOwnPane` - the caret already sits somewhere inside the claimant's
 * own pane. It got there because the user clicked something there (a host card,
 * a pane header button, the terminal body), and moving it to this pane's
 * "default" element would take it off whatever they just aimed at. Nothing to
 * do: the pane already has it.
 *
 * `caretInOverlay` - a menu, dialog or listbox holds the caret. Those are
 * PORTALED out of the pane that opened them, so `caretInsideOwnPane` cannot
 * see them: without this clause, clicking "New host" (or a pane header's
 * theme menu) in a pane that was not already the active one would open the
 * menu, activate the pane, and then yank the caret out of the menu one frame
 * later. An overlay owns the caret until it closes.
 */
export function caretHandoff(state: {
  /** The claimant is still the on-screen, active leaf. */
  stillOnScreen: boolean;
  /** The caret is already somewhere inside the claimant's own pane. */
  caretInsideOwnPane: boolean;
  /** A menu/dialog/listbox currently holds the caret. */
  caretInOverlay: boolean;
}): boolean {
  return state.stillOnScreen && !state.caretInsideOwnPane && !state.caretInOverlay;
}

/**
 * The two things this module asks a DOM element. Declared structurally, and in
 * METHOD syntax so a real `Element` satisfies it, because the alternative is a
 * contract whose only test would need a browser: `scripts/pane-caret-verify.ts`
 * hands the arbiter plain objects instead of standing up a DOM.
 */
export type CaretNode = {
  // `unknown`, not `CaretNode`: the DOM declares `Node.contains(other: Node |
  // null)`, and `Node` has no `closest`, so a `CaretNode` parameter here makes
  // a real element fail to satisfy this in BOTH directions. Widening the
  // parameter is what lets method bivariance accept `Element` unchanged.
  contains(other: unknown): boolean;
  closest(selector: string): CaretNode | null;
};

/**
 * One pane asking for the caret.
 *
 * Every field is a FUNCTION on purpose: all three are read at flush time, one
 * frame after the claim, so a claim can never carry a stale snapshot of the
 * thing it is claiming against. (This is the property `liveFocus` in
 * `useTerminalSession.ts` was introduced for, generalised - a ref read late
 * instead of a closure frozen early.)
 */
export type CaretClaim = {
  /** The claimant's pane box. Focus already inside it belongs to the user. */
  pane: () => CaretNode | null;
  /** Still the visible tab's active leaf? */
  stillOnScreen: () => boolean;
  /** Put the caret where this pane wants it. */
  take: () => void;
};

/** Identifies a claimant so a second claim replaces its first. A leaf id, or
 *  any stable object (a ref) for a pane that has no id of its own. */
export type CaretOwner = number | string | object;

export type CaretArbiter = {
  /** Ask for the caret. Applied one frame later, if still warranted. */
  claim: (owner: CaretOwner, claim: CaretClaim) => void;
  /** Withdraw a pending claim - a pane that unmounted, or went off screen
   *  before the frame it was waiting for. */
  release: (owner: CaretOwner) => void;
};

/** Selector for the overlay kinds that trap the caret while they are open.
 *  ARIA roles rather than Radix internals, so a version bump cannot quietly
 *  turn this into a selector that matches nothing. */
const OVERLAY_ROLES = '[role="menu"],[role="dialog"],[role="alertdialog"],[role="listbox"]';

/** Whoever holds the caret right now, or null outside a browser. */
function domCaret(): CaretNode | null {
  return typeof document === "undefined" ? null : document.activeElement;
}

/**
 * The arbiter, with its scheduler and its view of the caret injected.
 *
 * Injected because the deferral IS the fix: a check that cannot watch a claim
 * fail to run synchronously and then run one frame later cannot tell this apart
 * from the bug. `scripts/pane-caret-verify.ts` drives it with a hand-cranked
 * frame and a hand-built caret; `paneCaret` below is the same thing wired to
 * `requestAnimationFrame` and the real document.
 */
export function createCaretArbiter(
  defer: (run: () => void) => void,
  caretNow: () => CaretNode | null = domCaret,
): CaretArbiter {
  const pending = new Map<CaretOwner, CaretClaim>();
  let scheduled = false;

  const flush = (): void => {
    scheduled = false;
    // Drained BEFORE any `take()` runs: focusing something can commit React
    // state (the pane frame's `onFocus` re-points the active leaf), and a claim
    // that arrives during a flush belongs to the NEXT frame, not this one.
    const claims = [...pending.values()];
    pending.clear();
    for (const c of claims) {
      const caret = caretNow();
      const box = c.pane();
      if (
        !caretHandoff({
          stillOnScreen: c.stillOnScreen(),
          caretInsideOwnPane: !!box && !!caret && box.contains(caret),
          caretInOverlay: !!caret && caret.closest(OVERLAY_ROLES) !== null,
        })
      ) {
        continue;
      }
      c.take();
      // One caret, one owner. Two panes cannot both be the visible tab's active
      // leaf, so a second passing claim would mean the app disagrees with itself
      // about which leaf is active; taking the first and dropping the rest keeps
      // that disagreement from turning into two `focus()` calls that fight.
      return;
    }
  };

  return {
    claim(owner, claim) {
      pending.set(owner, claim);
      if (scheduled) return;
      scheduled = true;
      defer(flush);
    },
    release(owner) {
      pending.delete(owner);
    },
  };
}

/**
 * The app's arbiter.
 *
 * `requestAnimationFrame`, not `setTimeout(0)`: both run after the current task
 * (which is all the fix strictly needs - the mousedown default action has to
 * have happened), but a frame callback also lands BEFORE the paint that shows
 * the newly-visible tab, so the caret is never observably in the wrong place.
 */
export const paneCaret: CaretArbiter = createCaretArbiter((run) => {
  if (typeof requestAnimationFrame === "undefined") {
    run();
    return;
  }
  requestAnimationFrame(run);
});
