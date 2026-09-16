// One place the three record stores hand their dirty marks to, and one place
// the sync scheduler picks them up from.
//
// WHY THIS FILE EXISTS AT ALL, rather than the stores calling the scheduler:
// the three store singletons are constructed at module scope, so anything they
// use has to be importable from them - and `modules/hosts/adapters.ts` states
// the direction the dependency must point in, "a store that imported a
// scheduler would put a network module behind every host edit, and every suite
// that builds this store would have to construct one". A store importing this
// file imports eight lines with no Tauri surface and no imports of its own.
//
// The scheduler registers itself in the other direction, which is the edge that
// is allowed: `modules/sync` may know about the stores.
//
// NOT A BUS. One sink, replaced rather than appended to, because there is one
// consumer by construction: `scheduler.ts` no-ops outside the `main` webview,
// so a second subscriber would be a second window applying pulls - the exact
// thing that guard exists to prevent.

import type { DirtyId } from "./tombstones";

/** The registered consumer, or nothing - which is the state in every webview
 *  but `main`, and in every verify script that builds a store. */
let sink: ((dirty: DirtyId[]) => void) | null = null;

/**
 * Route dirty marks to `next`, replacing whatever was there.
 *
 * `null` unregisters, which is what a teardown wants: a stale closure holding a
 * disposed scheduler would keep collecting marks nothing ever pushes.
 */
export function setDirtySink(next: ((dirty: DirtyId[]) => void) | null): void {
  sink = next;
}

/**
 * What a store's `persist` calls after a commit.
 *
 * NEVER THROWS, and that is the load-bearing part rather than politeness: this
 * runs at the end of a queued store write, so an exception here would surface
 * as a failed `upsertHost` - a record the user did save, reported as not saved,
 * because a background scheduler was unhappy.
 */
export function markDirty(dirty: DirtyId[]): void {
  if (!sink || dirty.length === 0) return;
  try {
    sink(dirty);
  } catch (e) {
    console.error("sync: the dirty sink threw", e);
  }
}
