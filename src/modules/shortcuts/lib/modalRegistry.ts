/**
 * VLT-30: open-modal registry.
 *
 * Registered from the two shared dialog primitives (`Dialog` in
 * components/ui/dialog.tsx, `AlertDialog` in components/ui/alert-dialog.tsx),
 * not from each individual dialog - so every dialog built on top of them is
 * covered automatically, including ones that don't exist yet. Read from
 * `useGlobalShortcuts`, the sole reader, which is why this lives next to it
 * in shortcuts/lib rather than the more generic src/lib: it has exactly one
 * module-external consumer pair (the two primitives) and one internal one.
 *
 * Without this, a global shortcut (e.g. Ctrl+W "close tab") fires straight
 * through an open dialog's capture-phase listener and mutates app state the
 * user can't see happen behind the modal - see the Hosts editor dialog +
 * Ctrl+W repro in VLT-30.
 *
 * COUNT, not boolean: two dialogs can legitimately be open at once (a
 * destructive-confirm AlertDialog stacked over a form Dialog). The inner one
 * closing must not re-enable shortcuts while the outer one is still up, so
 * this tracks how many are open rather than whether one is.
 */

let openCount = 0;

/**
 * Call when a dialog becomes open. Returns a release function to call when it
 * closes or unmounts. Idempotent - calling the same release twice (e.g. a
 * close effect's cleanup racing an unmount) only decrements once, so the
 * count can never be driven negative or under-released.
 *
 * Leak safety: callers register this from a `useEffect` keyed on the dialog's
 * `open` prop and return the release as the effect's cleanup. React runs
 * effect cleanups on unmount unconditionally, even when the component is torn
 * out of the tree without ever transitioning `open` back to false (e.g. a
 * parent conditionally stops rendering it). That guarantees the count is
 * decremented even on a non-graceful unmount, so a stuck-open dialog can never
 * permanently suppress shortcuts for the rest of the session.
 */
export function openModal(): () => void {
  openCount++;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    openCount--;
  };
}

/** True while at least one dialog registered via [[openModal]] is open. */
export function isModalOpen(): boolean {
  return openCount > 0;
}

/** Test-only escape hatch: reset between test cases so one test's leaked
 *  registration can't fail the next. Not used by app code. */
export function __resetModalRegistryForTest(): void {
  openCount = 0;
}
