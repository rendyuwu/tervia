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

export type ForwardRule = {
  /** Opaque, `f-` prefixed. */
  id: string;
  name: string;
  /** The SSH host this rides. Refused at the write unless it names a saved host
   *  whose protocol is "ssh" - see `store.ts`'s `upsertRule`. */
  hostId: string;
  /** 0 means "let the OS pick", which the page then shows once bound. Legal only
   *  here - `remotePort` has no such meaning and refuses 0 at the write. */
  localPort: number;
  remoteHost: string;
  remotePort: number;
  /**
   * Bring this rule up when that host's terminal connects, on the TERMINAL's own
   * session - which dies with the tab.
   *
   * Reproduces what `conn.forwards` used to do before the SSH/RDP unification
   * (accepted gap 1), and is the other half of that regression: the forward used
   * to ride the connection record itself, and splitting rules into their own
   * store (decision 7) is what makes a rule editable without the host it rides
   * being on screen, at the cost of needing this flag to say when it starts.
   */
  startWithHost: boolean;
  description?: string;
};

// No `type: "local"` field - see the 6f plan's §5 boundary 2 for the argument
// (only a local-to-remote forward is modelled today) and the read-time-adoption
// migration path a remote/dynamic variant would take later, the same shape
// `hosts/types.ts`'s `hostPins` already uses for its own read-time migration.
