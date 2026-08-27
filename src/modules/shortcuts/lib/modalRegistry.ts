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
 * A STACK, not a boolean and not a bare count (VLT-59): two dialogs can
 * legitimately be open at once (a destructive-confirm AlertDialog over a form
 * Dialog), so the inner one closing must not re-enable shortcuts while the
 * outer one is still up - which a count already gave. What a count could NOT
 * give is WHICH modal is on top, and that is the question the one exemption
 * from the gate turned out to need: `commandPalette.open` was exempted by the
 * chord's identity, so it opened the palette on top of the host editor. The
 * order is the whole point, so the stack is ordered by open time and the last
 * entry is the topmost.
 */

/** One open modal. `name` is null for the dialogs that never need naming - the
 *  gate only asks about the ones a chord may act on. */
type OpenModal = { name: string | null };

const stack: OpenModal[] = [];

/**
 * The name the Command Palette registers itself under. Lives here, beside the
 * stack, so the palette (which passes it to `Dialog`) and `useGlobalShortcuts`
 * (which asks whether it is on top) cannot drift to two different strings -
 * a typo would silently re-gate the palette's own toggle chord.
 */
export const COMMAND_PALETTE_MODAL = "commandPalette";

/**
 * Call when a dialog becomes open. `name` identifies it to `isTopModal` for the
 * one chord that is allowed to act on its own dialog through the gate; leave it
 * out for every other dialog, which only needs to be counted. Returns a release
 * function to call when it closes or unmounts. Idempotent - calling the same
 * release twice (e.g. a close effect's cleanup racing an unmount) only removes
 * the entry once, so the stack can never be under-released or corrupted.
 *
 * Removal is by identity, not by popping: a modal below the top can close first
 * (a form Dialog force-unmounted while its confirm is up), and popping would
 * then drop the wrong entry and leave the closed one registered forever.
 *
 * Leak safety: callers register this from a `useEffect` keyed on the dialog's
 * `open` prop and return the release as the effect's cleanup. React runs
 * effect cleanups on unmount unconditionally, even when the component is torn
 * out of the tree without ever transitioning `open` back to false (e.g. a
 * parent conditionally stops rendering it). That guarantees the entry is
 * removed even on a non-graceful unmount, so a stuck-open dialog can never
 * permanently suppress shortcuts for the rest of the session.
 */
export function openModal(name?: string): () => void {
  const entry: OpenModal = { name: name ?? null };
  stack.push(entry);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const at = stack.indexOf(entry);
    if (at !== -1) stack.splice(at, 1);
  };
}

/** True while at least one dialog registered via [[openModal]] is open. */
export function isModalOpen(): boolean {
  return stack.length > 0;
}

/**
 * True when the most recently opened still-open modal was registered under
 * `name`. False when nothing is open at all, so a caller must ask
 * [[isModalOpen]] first if "no modal" is a different answer for it - which it
 * is for the shortcut gate, where no modal means the gate does not apply
 * rather than that an exemption does.
 */
export function isTopModal(name: string): boolean {
  const top = stack[stack.length - 1];
  return top !== undefined && top.name === name;
}

/** Test-only escape hatch: reset between test cases so one test's leaked
 *  registration can't fail the next. Not used by app code. */
export function __resetModalRegistryForTest(): void {
  stack.length = 0;
}
