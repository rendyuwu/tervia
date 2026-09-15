// What a delete leaves behind, shared by the three stores whose records sync.
//
// Here rather than in one of them for the reason `recoveredStore.ts` is here:
// `modules/hosts`, `modules/vault` and `modules/forwards` all need the same
// record shape and the same window, and three spellings of the 90-day constant
// is exactly the kind of thing that drifts apart - after which two devices
// disagree about when a delete stops being true.
//
// A delete has to leave something behind at all because the alternative is
// indistinguishable from never having had the record: a device that has not
// pulled since would treat its own copy as new and push it back.

/** One dropped record, in the shape a merge can compare against a live one. */
export type Tombstone = {
  /** The id the dropped record had. */
  id: string;
  /**
   * Which kind of record it was.
   *
   * A plain `string` here rather than a union of the five record kinds, because
   * this layer must not learn what a host or a vault key is - each module
   * exports its own constant and hands it in. Nothing enforces that; it is a
   * convention, and it is stated here because there is no check to point at.
   */
  kind: string;
  /** Unix ms, stamped by the store that dropped the record - never by a caller.
   *  See {@link TOMBSTONE_TTL_MS} for how long it stays meaningful. */
  deletedAt: number;
};

/** Where each store files its tombstones. One key per store FILE, so the three
 *  lists never collide. */
export const TOMBSTONES_KEY = "tombstones";

/**
 * How long a tombstone outlives the record it names.
 *
 * A device offline longer than this can resurrect a record deleted while it was
 * away - accepted rather than solved, see `KNOWN-LIMITS.md`.
 */
export const TOMBSTONE_TTL_MS = 90 * 24 * 60 * 60 * 1000;

/** A shape check rather than a cast: this reads a file the user can edit, and a
 *  row missing `deletedAt` would compare as deleted at the epoch forever. */
function isTombstone(v: unknown): v is Tombstone {
  if (typeof v !== "object" || v === null) return false;
  const t = v as Partial<Tombstone>;
  return typeof t.id === "string" && typeof t.kind === "string" && typeof t.deletedAt === "number";
}

/**
 * The tombstones still inside the window, from whatever the file held.
 *
 * FILTER-ON-READ is the whole pruning mechanism on the read side, and it is why
 * no store has a load-time maintenance pass: `RecoveredStoreIo` has no load
 * hook, and adding one would cost a store write, a `.bak` snapshot and a
 * cross-window changed event on every launch where anything happened to expire.
 * An expired row sitting in the file is never observable regardless of which
 * write last touched the key - but it is also never reclaimed in a store that
 * sees no further deletes. Accepted, and there is an entry in `KNOWN-LIMITS.md`
 * to retire when any store gains a load-time pass for another reason.
 */
export function livingTombstones(raw: unknown, now = Date.now()): Tombstone[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter(isTombstone).filter((t) => now - t.deletedAt < TOMBSTONE_TTL_MS);
}

/**
 * `current` with `added` appended and everything expired dropped - the list to
 * persist. The prune-on-write half: a write that was happening anyway compacts
 * the file for free.
 *
 * Every store call site passes a list that {@link livingTombstones} already
 * filtered, so in practice the filter here removes nothing; it is here so the
 * invariant belongs to this function rather than to the discipline of its
 * callers. Retire the entry in `KNOWN-LIMITS.md` about unreclaimed bytes and
 * this is the pair of functions that changes.
 */
export function withTombstone(
  current: Tombstone[],
  added: Tombstone[],
  now = Date.now(),
): Tombstone[] {
  return [...livingTombstones(current, now), ...added];
}

/**
 * `current` with every tombstone naming one of `ids` removed and everything
 * expired dropped, or `null` when no NAMED ID was there.
 *
 * The `null` is what keeps an upsert from writing this key at all, and that is
 * not tidiness. `createFileKeyValueStore` in `fileKeyValueStore.ts` gives up
 * after a few contended attempts and then writes this session's pending keys
 * over a stale baseline, losing another window's update - so every key an
 * upsert sets is a key it can clobber. Stamping the tombstones key on every
 * upsert would widen that from the record list alone to the record list plus a
 * tombstone another window just committed, for a write that is almost always a
 * no-op.
 *
 * THE NULL IS KEYED ON THE NAMED ID, AND ON NOTHING ELSE. If expiry also made
 * the result non-null, an upsert that clears nothing would rewrite the key
 * whenever anything happened to expire - which is most of the time once a store
 * is a few months old, and is exactly what the `null` exists to prevent. The
 * filter that follows is {@link withTombstone}'s defence-in-depth, on the same
 * terms: every store call site has already passed its list through
 * {@link livingTombstones}, so it removes nothing today. This and
 * {@link withTombstone} are the only things that compact the stored list at all,
 * which is the entry in `KNOWN-LIMITS.md` about bytes an untouched store never
 * reclaims.
 */
export function withoutTombstone(
  current: Tombstone[],
  ids: string[],
  now = Date.now(),
): Tombstone[] | null {
  const named = new Set(ids);
  if (!current.some((t) => named.has(t.id))) return null;
  return livingTombstones(current, now).filter((t) => !named.has(t.id));
}
