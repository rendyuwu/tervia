// What a delete leaves behind, shared by the three stores whose records sync -
// and, below it, the two shapes the sync path speaks to those same three stores
// in: what a pull LANDS, and what a write owes a push.
//
// Here rather than in one of them for the reason `recoveredStore.ts` is here:
// `modules/hosts`, `modules/vault` and `modules/forwards` all need the same
// record shape and the same window, and three spellings of the 90-day constant
// is exactly the kind of thing that drifts apart - after which two devices
// disagree about when a delete stops being true. The landing shapes are here on
// the same grounds, plus one of their own: all three stores already import this
// file, so nothing gains an import edge on a sync module to speak to it.
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

/**
 * The tombstone list one apply pass should persist, or `null` when nothing it
 * landed touches this key.
 *
 * The `null` is {@link withoutTombstone}'s, for the reason that one exists:
 * every key a write sets is a key a contended save can put over a stale
 * baseline, so an apply that landed only live records must not stamp this one.
 *
 * `added` REPLACES a stored tombstone naming the same id rather than joining it.
 * The landing carries the remote's `deletedAt`, which is the answer both devices
 * have to agree on; keeping the local copy beside it would leave the list saying
 * one delete happened twice, at two times, and the earlier one would expire
 * first.
 */
export function landedTombstones(
  current: Tombstone[],
  cleared: string[],
  added: Tombstone[],
  now = Date.now(),
): Tombstone[] | null {
  const replaced = new Set(added.map((t) => t.id));
  const base = added.length > 0 ? current.filter((t) => !replaced.has(t.id)) : current;
  const withoutCleared = withoutTombstone(base, cleared, now);
  if (added.length === 0) return withoutCleared;
  return withTombstone(withoutCleared ?? base, added, now);
}

/**
 * One record a push still owes the remote.
 *
 * `kind` is the same string a {@link Tombstone} uses, so a dirty mark and a
 * tombstone naming the same record agree without a second vocabulary - the
 * remote object a push writes is named from exactly these two fields, whether
 * what it carries is a record or a delete.
 *
 * A RECORD ID rather than a store, which is the whole reason this type exists:
 * a store's `persist` takes whole arrays, so a hook there could only ever say
 * "something in this file changed" and every edit would push the entire
 * inventory.
 */
export type DirtyId = { kind: string; id: string };

/**
 * One already-merged record or tombstone on its way INTO a store, carrying the
 * timestamp the REMOTE gave it.
 *
 * The timestamp is the point. Every mutator in the three stores overwrites what
 * its caller supplied and stamps its own clock, which is right for every caller
 * that originates what it writes - and wrong for the one that does not: a pulled
 * record stamped locally outranks the copy it came from, and a pulled tombstone
 * restarts the expiry window on every device that receives it.
 *
 * `id` is on the record arm rather than read off `record`, because the two can
 * disagree and a landing that refuses for that reason still has to be able to
 * NAME what it refused. `record` arrives from another device through a file and
 * a network, so "not an object at all" is a state this type cannot exclude and
 * `record.id` is not reachable in it.
 *
 * `updatedAt` here WINS over any `updatedAt` inside `record`. The record's own
 * copy is whatever the remote device serialized; this one is what the merge
 * decided, and only one of them can be what gets stored.
 *
 * `secrets` is the carried private-key body, keyed by the secret field name it
 * belongs at. Accepted and IGNORED for now - the keychain write that consumes it
 * arrives with the settings surface that lets a user opt into carrying bodies at
 * all. It is in the type from the start so that arrival is an implementation
 * rather than a second signature change rippling through every call site.
 */
export type RemoteLanding<T> =
  | { deleted: false; id: string; record: T; updatedAt: number; secrets?: Record<string, string> }
  | { deleted: true; tombstone: Tombstone };

/** One landing a store would not apply, named the way a push names an object so
 *  the caller can exclude it from what it records as applied. */
export type RemoteLandingRefusal = { kind: string; id: string; reason: string };

/**
 * The landing's refusal, or `null` when there is nothing wrong with it.
 *
 * FOUR CONDITIONS, and they are the whole set: an id that disagrees with the
 * record carrying it, a `record` that is not an object, a tombstone with no
 * usable `deletedAt`, and a tombstone of a kind this argument does not own. A
 * fifth is a deliberate act, not a tidy-up - what is deliberately NOT here is
 * every REFERENCE guard the ordinary mutators run. A rule arriving before the
 * host it names is normal: the landing set is a snapshot of another device's
 * consistent inventory, and the order within one pull is an artifact of a
 * listing.
 *
 * `kind` is a parameter rather than something read off the landing because the
 * record arm has no kind to read - the array a landing arrived in is what says
 * what it is. That is also what the fourth condition checks: a tombstone routed
 * into the wrong array would otherwise delete whatever local record happened to
 * share its id, in a store that never held the record it names.
 *
 * RETURNED, never thrown, and that is the load-bearing half. Every store applies
 * its landings inside one queued write; a throw from the middle of that loses
 * every other landing in the same set, including the good ones.
 */
export function landingRefusal<T extends { id: string }>(
  landing: RemoteLanding<T>,
  kind: string,
): RemoteLandingRefusal | null {
  if (landing.deleted) {
    const grave = landing.tombstone;
    if (grave.kind !== kind) {
      return {
        kind: grave.kind,
        id: grave.id,
        reason: `a ${grave.kind} tombstone is not a ${kind}`,
      };
    }
    if (typeof grave.deletedAt !== "number" || !Number.isFinite(grave.deletedAt)) {
      return { kind, id: grave.id, reason: "the tombstone carries no usable deletedAt" };
    }
    return null;
  }
  const record: unknown = landing.record;
  if (typeof record !== "object" || record === null) {
    return { kind, id: landing.id, reason: "the landing carries no record object" };
  }
  if ((record as { id?: unknown }).id !== landing.id) {
    return { kind, id: landing.id, reason: "the record names a different id than the landing" };
  }
  return null;
}
