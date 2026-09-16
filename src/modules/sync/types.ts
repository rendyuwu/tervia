// The vocabulary the sync module speaks, and the mirrors of the two Rust
// command payloads.
//
// KEPT IN LOCKSTEP BY HAND with `src-tauri/src/modules/sync/engine.rs`, the same
// way `src/lib/ipc.ts` mirrors the filesystem payloads - and for the same
// reason: `tsc` cannot see across the IPC boundary, so a field renamed on one
// side is `undefined` on the other with no error anywhere. Each type below names
// the Rust type it mirrors.

/** Where the sync module's own settings live. Its own file, so a contended
 *  write here can never clobber a host or a vault key. */
export const SYNC_STORE_PATH = "tervia-sync.json";

/** The keychain service the provider credentials and the passphrase go under.
 *  Sync's own, beside `tervia-hosts` and `tervia-vault`. */
export const SYNC_KEYRING_SERVICE = "tervia-sync";

/** Keys inside {@link SYNC_STORE_PATH}. Separate keys rather than one blob, so a
 *  status write and a config write never contend for the same value. */
export const SYNC_CONFIG_KEY = "config";
export const SYNC_ETAGS_KEY = "etags";
export const SYNC_DIRTY_KEY = "dirty";
export const SYNC_STATUS_KEY = "status";

/**
 * How long an edit waits for its neighbours before a push goes out.
 *
 * Five seconds, because the unit a user produces is a burst: an editor save
 * writes one record and the same hand often writes two or three more. Per-edit
 * pushes would make that three round trips where one would do.
 */
export const PUSH_DEBOUNCE_MS = 5000;

/**
 * The floor between two focus-driven pulls.
 *
 * Without it, alt-tabbing is a poll loop wearing an event's clothes -
 * `CONTRIBUTING.md` rejects exactly that shape - and each iteration is a LIST
 * against the user's storage.
 */
export const FOCUS_INTERVAL_MS = 60_000;

/**
 * The non-secret half of a sync configuration.
 *
 * WHAT IS NOT HERE: the passphrase, the access key id and the secret access
 * key. Those go to the keychain under {@link SYNC_KEYRING_SERVICE}, because this
 * file sits in the app data directory in plain JSON beside the host list.
 *
 * `enabled` off means NO NETWORK, checked before anything is invoked rather
 * than inside the Rust commands - see `KNOWN-LIMITS.md` for what that costs.
 */
export type SyncConfig = {
  enabled: boolean;
  /** The provider id `build` in `src-tauri/src/modules/sync/provider.rs`
   *  dispatches on. One value today. */
  provider: string;
  endpoint: string;
  region: string;
  bucket: string;
  /** Where in the bucket this device's inventory lives. May be empty. */
  prefix: string;
  /** Whether the endpoint honours a conditional write. A STORED USER TOGGLE and
   *  never a probe - see `Caps` in `src-tauri/src/modules/sync/provider.rs`. */
  cas: boolean;
  /**
   * Whether private key bodies travel at all.
   *
   * ONE TOGGLE, BOTH DIRECTIONS. Off means this device neither publishes a body
   * nor accepts one. A send-only reading would break the published opt-in and,
   * worse, make the keychain comparison asymmetric: only the local side's
   * `secrets` would ever be populated, so `secretsChanged` would be true on
   * every pull and every pull would rewrite the whole secrets file.
   */
  carrySecrets: boolean;
};

/** A device with sync never configured. Off, and naming nothing. */
export const DEFAULT_SYNC_CONFIG: SyncConfig = {
  enabled: false,
  provider: "s3",
  endpoint: "",
  region: "",
  bucket: "",
  prefix: "",
  cas: false,
  carrySecrets: false,
};

/**
 * What the settings window renders, written by `main` and read by settings.
 *
 * IN THE STORE RATHER THAN IN A COMMAND, because neither number is reachable
 * from Rust: the apply runs in `main`'s TypeScript, so a Rust-side status could
 * see neither the pending count nor the quarantine list. That is why there is no
 * `sync_status` command.
 */
export type SyncStatus = {
  lastPullAt: number | null;
  lastPushAt: number | null;
  /** Records the remote does not yet hold this device's copy of. */
  pending: number;
  /** Remote objects this device could not read, by their opaque names. */
  quarantine: { name: string; reason: string }[];
  /** Records this device holds that the remote has no object for and that are
   *  older than the tombstone window - reported, never deleted. */
  stale: { kind: string; id: string }[];
  lastError: string | null;
};

export const EMPTY_SYNC_STATUS: SyncStatus = {
  lastPullAt: null,
  lastPushAt: null,
  pending: 0,
  quarantine: [],
  stale: [],
  lastError: null,
};

/**
 * Mirrors Rust `Envelope` (`src-tauri/src/modules/sync/model.rs`).
 *
 * `device` is OPTIONAL here and never set on this side: `sync_push` stamps it
 * over whatever arrives, because the prune deletes remote objects on the
 * strength of it. So an inbound envelope carries one and an outbound envelope
 * does not, and this side never has to ask what this device is called.
 */
export type Envelope = {
  v: number;
  kind: string;
  id: string;
  updatedAt?: number;
  device?: string;
  deleted: boolean;
  record: unknown;
  secrets?: Record<string, string>;
};

/** [`WIRE_VERSION`] in that same file. A value check on both sides, never an
 *  assumption. */
export const WIRE_VERSION = 1;

/** Mirrors Rust `Reconciled` + `Outcome`, which serialize flattened into one
 *  object tagged by `outcome`. */
export type Reconciled = { kind: string; id: string } & (
  | {
      outcome: "merged";
      envelope: Envelope;
      /** Drives the STORE write. */
      changed: boolean;
      /** Drives the KEYCHAIN write, which the carry toggle gates. */
      secretsChanged: boolean;
      /** Whether the remote object still has to be brought up to the winner. */
      republish: boolean;
    }
  | { outcome: "remoteOnly"; envelope: Envelope }
  | { outcome: "localOnly"; stale: boolean }
);

/** Mirrors Rust `PullReport`. */
export type PullReport = {
  records: Reconciled[];
  /** `kind:id` to etag. Keyed so this side can compute it without an object
   *  name, which is an HMAC under a key this side never holds. */
  etags: Record<string, string>;
  quarantined: { name: string; reason: string }[];
  pruned: number;
  pending: number;
};

/** Mirrors Rust `PushFailure`. Named because the scheduler routes these back
 *  into the dirty set and out of the etag map, and needs to say so in a type. */
export type PushFailure = { kind: string; id: string; reason: string };

/** Mirrors Rust `PushReport`. */
export type PushReport = {
  etags: Record<string, string>;
  failed: PushFailure[];
};

/**
 * The two Rust commands, as a port.
 *
 * TWO NAMED METHODS rather than one `invoke(command, args)`, and that is not
 * decoration: `scripts/command-registry-verify.ts` reads the command name as a
 * LITERAL at the `invoke` call and pins every site that passes a variable
 * instead. A generic port would make this module such a site, and the pin would
 * then be the only thing tying two registered commands to a caller.
 *
 * It is also what the checks count: "with sync off, nothing is invoked" is a
 * measured zero on these two, not a consequence of nobody calling.
 */
export type SyncCommands = {
  pull(envelopes: Envelope[], etags: Record<string, string>): Promise<PullReport>;
  push(envelopes: Envelope[], etags: Record<string, string>): Promise<PushReport>;
};

/** Where one record sits in the etag map. Mirrors `slot` in
 *  `src-tauri/src/modules/sync/engine.rs`; the `:` is unambiguous because no
 *  record kind contains one. */
export function etagSlot(kind: string, id: string): string {
  return `${kind}:${id}`;
}
