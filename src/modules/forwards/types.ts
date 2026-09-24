// The forwards store's own vocabulary: one record per saved port-forward rule.
//
// A rule rides an SSH host rather than owning a connection of its own - the
// credential to open it comes from the host it names, resolved through
// `modules/ssh/tunnel.ts` -> `resolveSshAuth`, exactly the path an ordinary SSH
// connect already takes. So this module holds no secret and imports no keychain
// port: see `adapters.ts` for why that is a deliberate absence rather than an
// oversight.

export const FORWARDS_STORE_PATH = "tervia-forwards.json";
export const FORWARDS_KEY = "rules";

export type ForwardRuleType = "remote" | "dynamic";

export type ForwardRule = {
  /** Opaque, `f-` prefixed. */
  id: string;
  name: string;
  /** The SSH host this rides. Refused at the write unless it names a saved host
   *  whose protocol is "ssh" - see `store.ts`'s `upsertRule`. */
  hostId: string;
  /** Absent means a local (`-L`) forward - the shape every field below this
   *  one already had, unchanged. `"remote"` is `-R`, `"dynamic"` is `-D`.
   *  Adopted at read time, no migration - see the footer. */
  type?: ForwardRuleType;
  /**
   * `-L`: the local port THIS MACHINE binds; 0 means "let the OS pick", which
   *  the page then shows once bound.
   * `-D`: the local SOCKS5 listen port THIS MACHINE binds; the same 0-means-
   *  auto convention as `-L`'s.
   * `-R`: unused - the port `-R` binds is on the SERVER; see `bindPort`.
   */
  localPort: number;
  /**
   * `-L`: the host each accepted connection is dialled to, resolved by the
   *  SSH SERVER.
   * `-R`/`-D`: unused - forced to `""`. A `-R` rule's own dial target is
   *  {@link targetHost}, in a field `-L` never wrote, so an older build that
   *  does not know `type` reads this row through its own unconditional `-L`
   *  refusal (blank `remoteHost`) and drops it instead of silently opening
   *  it as a working `-L`.
   */
  remoteHost: string;
  /** Paired with {@link remoteHost}; never 0 on `-L` - the side that is
   *  DIALLED is never "let something else pick". Forced to `0` for `-R`/`-D`,
   *  for the same older-build-refusal reason {@link remoteHost} is forced
   *  blank. */
  remotePort: number;
  /** `-R` only: the host THIS MACHINE dials for each connection the server
   *  accepts - same ROLE `-L`'s {@link remoteHost} has, just dialled by the
   *  other party. Never blank when `type === "remote"`. Absent for `-L`/`-D`. */
  targetHost?: string;
  /** Paired with {@link targetHost}; never 0 when `type === "remote"` - a
   *  dial target is never "let something else pick". Absent for `-L`/`-D`. */
  targetPort?: number;
  /** `-R` only: the address the SERVER's listener binds to. Blank behaves
   *  as "localhost" - normalised where a rule is actually opened, not here -
   *  and `GatewayPorts no` on an ordinary server restricts the bind to
   *  loopback regardless of what is asked for. Absent for `-L`/`-D`. */
  bindAddress?: string;
  /** `-R` only: the port the SERVER listens on; 0 means "let the SERVER
   *  pick", surfaced once bound the same way `-L`'s auto `localPort` is.
   *  Absent for `-L`/`-D`. */
  bindPort?: number;
  /**
   * Bring this rule up when that host's terminal connects, on the TERMINAL's own
   * session - which dies with the tab.
   *
   * Reproduces what `conn.forwards` used to do before the SSH/RDP unification,
   * and is the other half of that regression: the forward used
   * to ride the connection record itself, and splitting rules into their own
   * store is what makes a rule editable without the host it rides
   * being on screen, at the cost of needing this flag to say when it starts.
   *
   * `-R`/`-D` rules do not ride this path yet - `autostart.ts`'s
   * `startHostForwards` skips them with a banner rather than starting them;
   * see `KNOWN-LIMITS.md`.
   *
   * Mutually exclusive with {@link startWithApp} - `store.ts`'s `upsertRule`
   * refuses a rule with both `true`.
   */
  startWithHost: boolean;
  /**
   * Bring this rule up once, when the app itself finishes starting - no
   * terminal tab required, dialled headless through `ssh/tunnel.ts` by
   * `src/app/hooks/useForwardsAutostart.ts`, the same call `controller.ts`'s
   * `startRule` already makes for a page Start. A bind that fails here re-enters
   * `controller.ts`'s own backoff ladder (`FORWARD_RECONNECT_BACKOFF_MS`)
   * instead of being left down; see that file's header for the classification
   * that gates it.
   *
   * Absent means `false` - the read-time-adoption shape the footer describes.
   * Mutually exclusive with {@link startWithHost}; `store.ts`'s `upsertRule`
   * refuses a rule with both `true`.
   */
  startWithApp?: boolean;
  description?: string;
  /** Unix ms of the last change, stamped by the store on every write. Absent is
   *  not zero and is never backfilled on read - the read-time adoption the note
   *  below describes, and `HostBase.updatedAt` in `modules/hosts/types.ts`
   *  carries the full reasoning. */
  updatedAt?: number;
};

/** What a rule is called in a tombstone's `kind`. */
export const RULE_TOMBSTONE_KIND = "rule";

// A remote (`-R`) or dynamic (`-D`) forward is `type: "remote"` / `"dynamic"`
// on this same record, adopted at read time rather than by a migration - the
// same shape `hosts/types.ts`'s `hostPins` already uses for its own read-time
// migration. See `type`'s own doc above for the vocabulary, and `store.ts`'s
// `upsertRule` for what each type refuses. `startWithApp` (issue #77) is the
// same read-time-adoption shape again: absent reads as `false`, no migration.
