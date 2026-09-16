// Record in, envelope out, and back again.
//
// PURE, and loadable under plain node: no Tauri import, no store, no keychain.
// Everything here is a function of its arguments, which is what lets
// `scripts/sync-scheduler-verify.ts` drive the whole round trip without a
// runtime - and what keeps the one decision that matters, which fields travel,
// in a place a check can reach.

import { type RemoteLanding, type Tombstone } from "@/lib/tombstones";

import { WIRE_VERSION, type Envelope } from "./types";

/**
 * Fields a record carries that describe THIS MACHINE rather than the record.
 *
 * MIRRORS `DEVICE_LOCAL_FIELDS` in `src-tauri/src/modules/sync/model.rs`, and
 * the duplication is not laziness: the Rust side strips on the way out so no
 * caller can publish a trust pin by forgetting to, and this side strips so the
 * two sides of the merge are symmetric. Without this one, the local envelope
 * would still carry this device's `pins` while every remote copy has them
 * stripped, so `changed` would be true on every pull and every pull would
 * rewrite the host file.
 *
 * `scripts/sync-scheduler-verify.ts` reads both spellings and refuses a drift.
 */
export const DEVICE_LOCAL_FIELDS = [
  "pins",
  "lastConnectedAt",
  "lastFingerprint",
  "certFingerprint",
] as const;

/** `record` with every device-local field gone. A copy: the caller's record is
 *  the one in the store, and stripping it in place would delete the pins. */
function stripDeviceLocal(record: object): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(record as Record<string, unknown>) };
  for (const field of DEVICE_LOCAL_FIELDS) delete out[field];
  return out;
}

/**
 * One live record on its way out.
 *
 * `secrets` is the carried body, already read from the keychain by the caller.
 * A PARAMETER rather than a read, because this file holds no port: the toggle
 * that decides whether a body travels at all, and the keychain call behind it,
 * belong to the layer that has both.
 */
export function recordEnvelope(
  kind: string,
  record: { id: string; updatedAt?: number },
  secrets?: Record<string, string>,
): Envelope {
  // NO `device`. `sync_push` stamps it, so there is nothing here for a webview
  // to set wrong and no command for it to have to ask.
  const envelope: Envelope = {
    v: WIRE_VERSION,
    kind,
    id: record.id,
    deleted: false,
    record: stripDeviceLocal(record),
  };
  // ABSENT IS NOT ZERO, on this side too: a record written before the field
  // existed must order below every real stamp, and backfilling one here would
  // make it outrank the copies it should lose to.
  if (typeof record.updatedAt === "number") envelope.updatedAt = record.updatedAt;
  if (secrets && Object.keys(secrets).length > 0) envelope.secrets = secrets;
  return envelope;
}

/** One delete on its way out. A tombstone travels as an envelope like anything
 *  else, which is what lets a delete and an edit resolve through one merge. */
export function tombstoneEnvelope(tombstone: Tombstone): Envelope {
  return {
    v: WIRE_VERSION,
    kind: tombstone.kind,
    id: tombstone.id,
    updatedAt: tombstone.deletedAt,
    deleted: true,
    record: null,
  };
}

/**
 * One envelope on its way IN, or `null` when it cannot be landed at all.
 *
 * The `null` is the unstamped-tombstone case, and it is reachable: `merge`
 * refuses one and quarantines it, but a `RemoteOnly` object never goes through
 * the merge, so the only thing standing between a corrupt or hostile remote and
 * a `deletedAt` of `undefined` is this check. `livingTombstones` requires a
 * number, so such a row would be written to the file and then filtered out of
 * every read of it - the delete lost on this device while the caller records
 * the object as applied.
 *
 * A LIVE RECORD WITH NO STAMP IS LANDED AT ZERO rather than refused. Zero is
 * the honest reading of "written before the field existed": it orders below
 * everything, so the first edit on any device outranks it. Refusing would leave
 * the record unlandable forever, which is the worse of the two.
 */
export function landingOf<T extends { id: string }>(envelope: Envelope): RemoteLanding<T> | null {
  if (envelope.deleted) {
    if (typeof envelope.updatedAt !== "number") return null;
    return {
      deleted: true,
      tombstone: { id: envelope.id, kind: envelope.kind, deletedAt: envelope.updatedAt },
    };
  }
  const landing: RemoteLanding<T> = {
    deleted: false,
    id: envelope.id,
    record: envelope.record as T,
    updatedAt: typeof envelope.updatedAt === "number" ? envelope.updatedAt : 0,
  };
  return envelope.secrets ? { ...landing, secrets: envelope.secrets } : landing;
}
