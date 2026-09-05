/**
 * Self-check for RDP over SSH: the refcounted forward orchestrator in
 * `src/modules/ssh/tunnel.ts` and the dial resolution in `src/modules/rdp/dial.ts`.
 * Run: `npx tsx scripts/rdp-tunnel-verify.ts`.
 *
 * This one drives the real modules against a stand-in for the Tauri IPC bridge
 * (same idiom as `clipboard-read-verify` and `terminal-resize-verify`) rather
 * than testing pure helpers, because every property worth pinning here is about
 * WHEN a session is opened and closed - which is bookkeeping across two maps and
 * an await, not arithmetic.
 *
 * What it pins, and why each one is a bug that already happened or nearly did:
 *
 * 1. THE AUTH CALL SITE RUNS. `tunnel.ts`'s `authFields` call had never executed
 *    in the app's life - the module had zero callers - and it is the line that
 *    decides whether a private key or a password reaches the handshake. A typo
 *    there fails as "no credentials", on a path that reads keys out of the
 *    keychain. Now it is exercised for all three auth modes.
 *
 * 2. ONE SESSION PER BASTION, and it lives exactly as long as its consumers.
 *    Two forwards over one jump host must cost one russh session, and the first
 *    consumer to let go must not take the second one's tunnel with it.
 *
 * 3. REUSE TAKES A REFERENCE. The original `openForwardForConnection` returned
 *    an existing forward WITHOUT incrementing anything, while every close
 *    decremented: two RDP panes tunnelling to the same host shared one
 *    reference, so the first pane closed the session out from under the second.
 *    That is a black pane and a dead session for the survivor.
 *
 * 4. CONCURRENT OPENS SHARE ONE DIAL. Restoring a workspace with two RDP leaves
 *    behind one bastion runs both connects in the same tick. A map of resolved
 *    sessions has both miss and both dial, and the second overwrites the first -
 *    leaking a russh session whose reference count nobody can reach.
 *
 * 5. AN UNVERIFIED BASTION REFUSES, unless the caller can ask. The refusal is
 *    the old behaviour and stays the default; the RDP caller opts into the TOFU
 *    prompt because it has a dialog on screen anyway. Both directions matter:
 *    a caller that cannot ask must not park the backend on a question with no
 *    audience, and the prompt must pin the fingerprint on the right saved row.
 *
 * 6. THE TUNNEL CHANGES THE ADDRESS AND NOTHING ELSE. A tunnelled connect dials
 *    `127.0.0.1:<ephemeral>` but carries the same pinned certificate, because
 *    the pin belongs to the saved connection. Key it by address instead and the
 *    ephemeral port looks like a brand-new machine on every single connect: a
 *    TOFU prompt that never stops asking.
 *
 * 7. A RELEASE NAMES AN ENTRY, NOT A TARGET. `dropSession` deletes a
 *    connection's entries when the bastion dies, and the next consumer of the
 *    same target creates fresh ones under the same key. A release that only
 *    looked the key up spent the REINCARNATED entry's reference and closed a
 *    session another pane was using - and the pane whose late release did it had
 *    no way to know, since a parked TCP connection only fails on a keepalive.
 *    Over-release against a SPENT entry (item 3's mirror) was already covered;
 *    this is the re-created one, which the refs-at-zero guard cannot catch.
 *
 * 8. A JOINER LEARNS THE DIAL'S PROMPT IDS. Only the caller that starts a dial
 *    used to hear about its host-key questions, so a second pane riding the same
 *    handshake had nothing to abandon on its way out and depended entirely on
 *    the first one still being there. Both joiner shapes matter: a different
 *    target (which re-enters `sessionFor`) and the same target (which reuses the
 *    forward and never reaches it), plus catch-up for a question raised before
 *    the joiner arrived.
 *
 * 9. THE REQUESTED LOCAL PORT NAMES THE FORWARD. `forwardKey` was three parts,
 *    so a second rule onto the same target through a DIFFERENT local port took
 *    the reuse branch: it was handed the first rule's bound port and the first
 *    rule's claim, and nothing reported it. A rule pinned to 18081 ran on 18080
 *    and looked fine. Both directions matter - two callers asking for the SAME
 *    port (including 0, which is what the RDP path always sends) must still
 *    share one forward, or the reuse contract is gone.
 *
 * 10. STOP FREES THE PORT. An entry at zero references used to be kept, because
 *    `ssh_forward_open` had no counterpart: the port stayed bound while the
 *    session lived. With a Stop button on the page that is a rule whose own port
 *    is still held, so the next Start asks for it and the bind fails.
 *    `ssh_forward_close` closes one listener without touching the session, and
 *    it takes the BOUND port - which for an auto-port rule is not the one that
 *    was asked for.
 *
 * 11. AND THE RELEASE WAITS FOR IT. `ssh_forward_close` is keyed by bound port
 *    with no generation, so a close fired and forgotten can land on a listener
 *    that a re-open has since bound on that same port: a Stop returning before
 *    the backend heard it, then a Start on the same pinned port, reads from the
 *    page as "Start silently does nothing every other time". Only a
 *    stop while the dial is STILL IN FLIGHT can tell the two forms apart, which
 *    is what the last `[stop]` fixture sets up.
 */

export {};

import { HOSTS_KEY, HOSTS_STORE_PATH, type SshHost } from "../src/modules/hosts/types";
import type { VaultAuthMode } from "../src/modules/vault/types";

// ---------------------------------------------------------------------------
// Stand-in for the Tauri IPC bridge `@tauri-apps/api` calls into.
// ---------------------------------------------------------------------------

type Call = { cmd: string; args: Record<string, unknown> };
const calls: Call[] = [];
const callbacks = new Map<number, (payload: unknown) => void>();
let nextCallbackId = 1;

/** The hosts store's contents. Every row here is an SSH host - `tunnel.ts` only
 *  ever dials a bastion, and a saved id that names an RDP host is refused, not
 *  cast. Mutable: pinning a fingerprint writes through this, which is how
 *  prompt attribution is observed. */
type Row = SshHost;
let sshRows: Row[] = [];
/** Keychain, keyed the way `keyringAccount` builds it. */
let secrets: Record<string, string> = {};

/** `ssh_open` calls that have not been answered yet, so a test can park a dial
 *  the way a real host-key prompt does. */
type ParkedOpen = {
  input: Record<string, unknown>;
  channelId: number;
  resolve: (id: number) => void;
  reject: (e: unknown) => void;
};
let parkedOpens: ParkedOpen[] = [];
/** When false, `ssh_open` hangs until a test resolves it by hand. */
let autoAnswerOpen = true;
let nextSessionId = 100;
let nextLocalPort = 45000;

/** Where `appDataDir()` resolves for this harness. */
const APP_DATA_DIR = "/verify-app-data";
const HOSTS_FILE = `${APP_DATA_DIR}/${HOSTS_STORE_PATH}`;
/** Every store file other than the host list - the `.bak` snapshot, mostly.
 *  Kept as raw text because nothing here inspects it. */
const otherStoreFiles = new Map<string, string>();
/** Live `plugin:event|listen` subscriptions, by their event id, holding the
 *  `transformCallback` id to fire. */
const eventListeners = new Map<number, number>();

async function handleInvoke(cmd: string, args: Record<string, unknown>): Promise<unknown> {
  calls.push({ cmd, args });
  switch (cmd) {
    // The host store is a whole JSON file read and written through these two
    // commands (`lib/fileKeyValueStore.ts`), not a key/value plugin. `sshRows`
    // stays the harness's view of it so a test can still seed and inspect rows.
    case "plugin:path|resolve_directory":
      return APP_DATA_DIR;
    case "fs_read_file": {
      const path = args.path as string;
      const content =
        path === HOSTS_FILE ? JSON.stringify({ [HOSTS_KEY]: sshRows }) : otherStoreFiles.get(path);
      // Absent is an ERROR from the real command, and `tauriStoreFileIo.read`'s
      // catch is what sorts it into `missing`. It sorts on the `(os error N)`
      // suffix, so the wording is load-bearing: without it this reads as a file
      // that is there and would not open. Returning a value here would be read
      // as corruption instead.
      if (content === undefined) throw new Error(`No such file or directory (os error 2): ${path}`);
      return { kind: "text", content, size: content.length };
    }
    case "fs_write_file": {
      const path = args.path as string;
      const content = args.content as string;
      if (path === HOSTS_FILE) {
        const parsed = JSON.parse(content) as Record<string, unknown>;
        sshRows = (parsed[HOSTS_KEY] as Row[] | undefined) ?? [];
      } else otherStoreFiles.set(path, content);
      return undefined;
    }
    case "plugin:event|emit":
      return undefined;
    case "plugin:event|listen": {
      // Registered for real, not stubbed away: the store's cache is dropped by
      // a change event and nothing else, so a harness that swallowed these would
      // hold the first `reset`'s rows for the whole run.
      const id = nextCallbackId++;
      eventListeners.set(id, args.handler as number);
      return id;
    }
    case "plugin:event|unlisten":
      eventListeners.delete(args.eventId as number);
      return undefined;
    case "secrets_get_all":
      return (args.accounts as string[]).map((a) => secrets[a] ?? null);
    case "ssh_open": {
      const channelId = (args.onEvent as { id: number }).id;
      const input = args.input as Record<string, unknown>;
      return await new Promise<number>((resolve, reject) => {
        parkedOpens.push({ input, channelId, resolve, reject });
        if (autoAnswerOpen) resolve(nextSessionId++);
      });
    }
    // Answers the way `session.rs`'s forward does: a pinned port is bound
    // literally and comes back as itself, while `0` means "the OS picks" and
    // comes back as whatever it chose. Returning a fresh number either way
    // would make the port ASKED FOR and the port BOUND indistinguishable, and
    // `ssh_forward_close` takes the bound one.
    case "ssh_forward_open":
      return (args.localPort as number) || nextLocalPort++;
    case "ssh_forward_close":
      return true;
    case "ssh_close":
      return undefined;
    case "ssh_confirm_host_key":
      return undefined;
    default:
      throw new Error(`unexpected command in this harness: ${cmd}`);
  }
}

(globalThis as { window?: unknown }).window = {
  __TAURI_INTERNALS__: {
    transformCallback: (cb: (payload: unknown) => void) => {
      const id = nextCallbackId++;
      callbacks.set(id, cb);
      return id;
    },
    unregisterCallback: (id: number) => callbacks.delete(id),
    invoke: (cmd: string, args: Record<string, unknown>) => handleInvoke(cmd, args ?? {}),
  },
};

const { closeForwardForConnection, openForwardForConnection } =
  await import("../src/modules/ssh/tunnel");
const { openRdpDialTarget, rdpOpenInput } = await import("../src/modules/rdp/dial");
const { useHostKeyPrompt } = await import("../src/modules/ssh/hostKeyPrompt");
type RdpHostFixture = Parameters<typeof rdpOpenInput>[0];

// ---------------------------------------------------------------------------

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}
function assert(cond: boolean, msg: string): void {
  if (cond) console.log(`  ok: ${msg}`);
  else {
    console.error(`  FAIL: ${msg}`);
    failed++;
  }
}

/** Let every queued microtask and store write settle. The pin path is
 *  read-modify-write through a serialized queue, so one tick is not enough. */
async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0));
}

/**
 * Emit one backend event on a dial's event channel, the way the Rust side does.
 *
 * Tauri's `Channel` keys ordering off `index` and QUEUES anything out of turn,
 * so a second event reusing index 0 is silently swallowed - hence a counter per
 * channel rather than a literal at each call site.
 */
const emittedPerChannel = new Map<number, number>();
function emitOn(open: ParkedOpen, message: Record<string, unknown>): void {
  const index = emittedPerChannel.get(open.channelId) ?? 0;
  emittedPerChannel.set(open.channelId, index + 1);
  callbacks.get(open.channelId)!({ index, message });
}

function countOf(cmd: string): number {
  return calls.filter((c) => c.cmd === cmd).length;
}
function lastOf(cmd: string): Call | undefined {
  return [...calls].reverse().find((c) => c.cmd === cmd);
}
/** Every call of `cmd`, in the order the module made them, so a check can say
 *  what each one carried rather than only what the last one did. Two forwards
 *  differ in their arguments and not in their count, so a count alone would
 *  pass on two binds of the same port. */
function allOf(cmd: string): Call[] {
  return calls.filter((c) => c.cmd === cmd);
}

type RowOverrides = Partial<Omit<SshHost, "id" | "protocol" | "credential">> & {
  id: string;
  user?: string;
  authMode?: VaultAuthMode;
  hasPassword?: boolean;
  hasPrivateKey?: boolean;
  hasKeyPassphrase?: boolean;
};

/** One saved SSH host. The credential's `hostId` always tracks the row's own
 *  `id` - the store refuses a mismatch, and a fixture that got this wrong would
 *  fail every scenario below for the wrong reason. */
function row(over: RowOverrides): Row {
  const {
    id,
    user = "ubuntu",
    authMode = "agent",
    hasPassword = false,
    hasPrivateKey = false,
    hasKeyPassphrase = false,
    ...base
  } = over;
  return {
    protocol: "ssh",
    name: id,
    host: `${id}.example.com`,
    port: 22,
    lastFingerprint: `SHA256:pin-${id}`,
    ...base,
    id,
    credential: {
      kind: "inline",
      hostId: id,
      user,
      authMode,
      hasPassword,
      hasPrivateKey,
      hasKeyPassphrase,
    },
  };
}

/** Fresh world: no calls recorded, no live sessions. Every scenario below ends
 *  by releasing what it opened, so the module's own maps start empty too. */
function reset(rows: Row[]): void {
  calls.length = 0;
  parkedOpens = [];
  autoAnswerOpen = true;
  secrets = {};
  sshRows = rows;
  // Replacing the file behind a live store is what another window's commit
  // looks like, so say so. Without this the whole-file store keeps the rows it
  // read first and every scenario after the first is dialling the wrong world.
  for (const handler of eventListeners.values()) {
    callbacks.get(handler)?.({ event: "tervia://hosts-changed", id: handler, payload: null });
  }
}

// ---------------------------------------------------------------------------
console.log("[auth] the call site that had never executed");
// `tunnel.ts:61`'s `authFields(conn.authMode, secrets)`: dead code until now, on
// the path that reads private keys out of the keychain.
{
  reset([row({ id: "c-pass", authMode: "password", hasPassword: true })]);
  secrets["c-pass::password"] = "s3cret";
  const forward = await openForwardForConnection("c-pass", "10.0.0.9", 3389);
  const input = lastOf("ssh_open")?.args.input as Record<string, unknown>;
  check("a password connection sends its password", input.password, "s3cret");
  check("and not the agent", input.useAgent, false);
  check("and no key", [input.privateKey, input.privateKeyPassphrase], [null, null]);
  check(
    "pinned, so a changed key fails instead of prompting",
    input.expectedFingerprint,
    "SHA256:pin-c-pass",
  );
  check("a shell is opened alongside the forward", [input.cols, input.rows], [80, 24]);
  const fwd = lastOf("ssh_forward_open")?.args;
  check(
    "the forward binds an OS-chosen local port to the target",
    [fwd?.localPort, fwd?.remoteHost, fwd?.remotePort],
    [0, "10.0.0.9", 3389],
  );
  await closeForwardForConnection("c-pass", "10.0.0.9", 3389, 0, forward.claim);
}
{
  reset([row({ id: "c-key", authMode: "key", hasPrivateKey: true, hasKeyPassphrase: true })]);
  secrets["c-key::privateKey"] = "-----BEGIN OPENSSH PRIVATE KEY-----";
  secrets["c-key::keyPassphrase"] = "hunter2";
  const forward = await openForwardForConnection("c-key", "10.0.0.9", 3389);
  const input = lastOf("ssh_open")?.args.input as Record<string, unknown>;
  check(
    "a key connection sends key and passphrase",
    [input.privateKey, input.privateKeyPassphrase],
    ["-----BEGIN OPENSSH PRIVATE KEY-----", "hunter2"],
  );
  check("and no password", input.password, null);
  await closeForwardForConnection("c-key", "10.0.0.9", 3389, 0, forward.claim);
}
{
  reset([row({ id: "c-agent" })]);
  const forward = await openForwardForConnection("c-agent", "10.0.0.9", 3389);
  const input = lastOf("ssh_open")?.args.input as Record<string, unknown>;
  check(
    "an agent connection asks for the agent and nothing else",
    [input.useAgent, input.password, input.privateKey],
    [true, null, null],
  );
  await closeForwardForConnection("c-agent", "10.0.0.9", 3389, 0, forward.claim);
}

// ---------------------------------------------------------------------------
console.log("\n[sharing] two forwards over one bastion cost ONE session");
{
  reset([row({ id: "c-bastion" })]);
  const a = await openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  const b = await openForwardForConnection("c-bastion", "10.10.11.30", 5432);
  check("one dial", countOf("ssh_open"), 1);
  check("two forwards", countOf("ssh_forward_open"), 2);
  assert(a.localPort !== b.localPort, "each target gets its own local port");
  check("on the same session", a.sessionId, b.sessionId);

  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, a.claim);
  check("releasing one forward does not close the session", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.10.11.30", 5432, 0, b.claim);
  await settle();
  check("the last one does", countOf("ssh_close"), 1);

  // And the session is forgotten with it, so the next consumer dials afresh
  // rather than being handed a port nothing is listening on.
  const later = await openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  check("a later consumer opens a new session", countOf("ssh_open"), 2);
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, later.claim);
}

// ---------------------------------------------------------------------------
console.log(
  "\n[local ports] two rules onto one target through different local ports are two forwards",
);
// `forwardKey` was `connId|host|port`, so the local port a caller ASKED FOR was
// no part of a forward's identity. The second rule took the reuse branch, was
// handed the first one's bound port and the first one's claim, and nothing
// reported it: a rule pinned to 18081 ran on 18080 and looked fine.
{
  reset([row({ id: "c-bastion" })]);
  const a = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, { localPort: 18080 });
  const b = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, { localPort: 18081 });
  check("two forwards, not one reused", countOf("ssh_forward_open"), 2);
  check(
    "each one asked the backend for its OWN port, in order",
    allOf("ssh_forward_open").map((c) => c.args.localPort),
    [18080, 18081],
  );
  check("and a pinned port is bound literally", [a.localPort, b.localPort], [18080, 18081]);
  assert(a.claim !== b.claim, "two entries, so two claims - a release names one of them");
  check("over one session", [countOf("ssh_open"), a.sessionId === b.sessionId], [1, true]);

  // Each rule releases with its own port AND its own claim: the port finds the
  // entry, the claim proves it is the one this caller took its reference from.
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, a.claim);
  await settle();
  check("releasing one rule leaves the other's session up", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18081, b.claim);
  await settle();
  check("and the second one closes it - neither reference was lost", countOf("ssh_close"), 1);
}
{
  // The other direction, so the fix is not over-applied into "a forward per
  // caller". `0` is a value like any other in the key and means "the OS picks":
  // two auto-port callers onto one target legitimately share one forward, which
  // is what the RDP path has always done.
  reset([row({ id: "c-bastion" })]);
  const a = await openForwardForConnection("c-bastion", "10.0.0.9", 5432);
  const b = await openForwardForConnection("c-bastion", "10.0.0.9", 5432);
  check("two auto-port callers share one forward", countOf("ssh_forward_open"), 1);
  check("one entry, so one claim", a.claim, b.claim);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 0, a.claim);
  await settle();
  check("the first of them letting go leaves the session up", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 0, b.claim);
  await settle();
  check("the second closes it", countOf("ssh_close"), 1);
}
{
  // Same again for a pinned port, which is the case a rule actually is: two
  // consumers of ONE rule reuse its listener rather than fighting over the bind.
  reset([row({ id: "c-bastion" })]);
  const a = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, { localPort: 18080 });
  const b = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, { localPort: 18080 });
  check("and so do two callers pinning the SAME port", countOf("ssh_forward_open"), 1);
  check(
    "one entry, one claim, one port",
    [a.claim === b.claim, a.localPort, b.localPort],
    [true, 18080, 18080],
  );
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, a.claim);
  await settle();
  check("the first release leaves it up", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, b.claim);
  await settle();
  check("the second closes it", countOf("ssh_close"), 1);
}
{
  // The rest of the key still counts, and this is the half nothing else pins:
  // the `[sharing]` group's two targets differ in HOST as well as port, so a key
  // that dropped `remotePort` would still tell them apart there. Two ports on
  // ONE remote host through auto-ports is the case that catches it - a database
  // and an SSH shell on the same box behind a bastion.
  reset([row({ id: "c-bastion" })]);
  const db = await openForwardForConnection("c-bastion", "10.0.0.9", 5432);
  const shell = await openForwardForConnection("c-bastion", "10.0.0.9", 22);
  check("two remote ports on one host are two forwards", countOf("ssh_forward_open"), 2);
  assert(db.localPort !== shell.localPort, "each with a local port of its own");
  assert(db.claim !== shell.claim, "and an entry of its own");
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 0, db.claim);
  await settle();
  check("releasing one leaves the other up", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 22, 0, shell.claim);
  await settle();
  check("and the second closes the session", countOf("ssh_close"), 1);
}

// ---------------------------------------------------------------------------
console.log("\n[stop] releasing the last reference frees the port");
// An entry at zero references used to be KEPT, because `ssh_forward_open` had no
// counterpart and the port stayed bound while the session lived. With a Stop
// button on the page that is a rule whose own port is still held, so the next
// Start asks for it and the bind fails - the exact complaint
// `ssh_forward_close` was added for.
{
  reset([row({ id: "c-bastion" })]);
  // A SECOND rule on the same bastion, so the session outlives the stop. Without
  // it the last release calls `dropSession`, which clears the map wholesale, and
  // the rebind below would pass even with the entry kept at zero refs.
  const keep = await openForwardForConnection("c-bastion", "10.0.0.9", 22, { localPort: 18443 });
  const stopped = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, {
    localPort: 18080,
  });
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, stopped.claim);
  await settle();
  check("the backend is told to close ONE listener", countOf("ssh_forward_close"), 1);
  // The port is written out rather than read back off `stopped`, so a close that
  // named the session's other listener - or a forward re-opened on an OS-chosen
  // port - is a failure and not a tautology.
  check("naming the session and the port that was bound", lastOf("ssh_forward_close")?.args, {
    id: stopped.sessionId,
    boundPort: 18080,
  });
  check("and the session stays up for the rule that is still running", countOf("ssh_close"), 0);

  // Start again. The entry went with the port, so this binds rather than being
  // handed a port nothing is listening on.
  const restarted = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, {
    localPort: 18080,
  });
  check("a later Start binds the port again", countOf("ssh_forward_open"), 3);
  assert(restarted.claim !== stopped.claim, "as a new entry, with a claim of its own");
  check("still on the one session", countOf("ssh_open"), 1);

  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, restarted.claim);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 22, 18443, keep.claim);
  await settle();
  check("both listeners closed in the end", countOf("ssh_forward_close"), 3);
  check("and the session with the last of them", countOf("ssh_close"), 1);
}
{
  // A teardown that fires twice. The entry is deleted the moment its last
  // reference goes, so the second call has nothing to find - and either way it
  // must not tell the backend to close that port again, which after a Start
  // would be the NEW listener's.
  reset([row({ id: "c-bastion" })]);
  const one = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, { localPort: 18080 });
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, one.claim);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, one.claim);
  await settle();
  check("one close reaches the backend, not two", countOf("ssh_forward_close"), 1);
  check("and one session close", countOf("ssh_close"), 1);
}
{
  // The same stray release with the SESSION still up, which is the shape the
  // `[reuse]` group cannot express: there the last release closes the session,
  // so `dropSession` clears the map wholesale and the extra call has nothing to
  // find for that reason instead of this one.
  //
  // Two things have to hold together here. The entry is DELETED at zero refs, so
  // the stray call finds nothing; and the refs-at-zero guard above the decrement
  // still refuses one that does. Keep the entry and drop the guard and this is a
  // second decrement landing on the SESSION - which is at one reference for the
  // rule still running, so the stray teardown of a stopped rule takes the live
  // one's bastion with it.
  reset([row({ id: "c-bastion" })]);
  const keep = await openForwardForConnection("c-bastion", "10.0.0.9", 22, { localPort: 18443 });
  const stopped = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, {
    localPort: 18080,
  });
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, stopped.claim);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, stopped.claim);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, stopped.claim);
  await settle();
  check(
    "one listener closed, however many times the teardown fires",
    countOf("ssh_forward_close"),
    1,
  );
  check("and the rule still running keeps its bastion", countOf("ssh_close"), 0);

  // Which the survivor then closes on its own, so the guard has not simply
  // disabled releasing.
  await closeForwardForConnection("c-bastion", "10.0.0.9", 22, 18443, keep.claim);
  await settle();
  check("until it lets go itself", [countOf("ssh_forward_close"), countOf("ssh_close")], [2, 1]);
}
{
  // The auto-port case, and it is the one that separates the port ASKED FOR from
  // the port BOUND: a rule that pins nothing sends 0 and the backend answers
  // with what it chose. `ssh_forward_close` takes the bound one - 0 names no
  // listener, and a close carrying it would leave the port held.
  reset([row({ id: "c-bastion" })]);
  const auto = await openForwardForConnection("c-bastion", "10.0.0.9", 5432);
  assert(auto.localPort > 0, "the OS picked a port");
  check("which is not the one that was asked for", lastOf("ssh_forward_open")?.args.localPort, 0);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 0, auto.claim);
  await settle();
  check(
    "and the close names the BOUND port, not the requested 0",
    lastOf("ssh_forward_close")?.args,
    {
      id: auto.sessionId,
      boundPort: auto.localPort,
    },
  );
}
{
  // The claim's second consequence. `dropSession` deletes a connection's entries
  // when the bastion dies and the next consumer builds fresh ones under the same
  // key, so a release that only matched the key would hand the SUCCESSOR's bound
  // port to `ssh_forward_close` - dropping a listener the new pane is using, on
  // a port it legitimately re-bound.
  reset([row({ id: "c-bastion" })]);
  const paneA = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, {
    localPort: 18080,
  });
  emitOn(parkedOpens[0], { type: "exit", code: 255 });
  await settle();
  const paneB = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, {
    localPort: 18080,
  });
  assert(paneA.claim !== paneB.claim, "the re-created entry is a different generation");
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, paneA.claim);
  await settle();
  check("pane A's stale release closes no listener at all", countOf("ssh_forward_close"), 0);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, paneB.claim);
  await settle();
  check("pane B's own release closes its own", countOf("ssh_forward_close"), 1);
  check("naming pane B's session", lastOf("ssh_forward_close")?.args, {
    id: paneB.sessionId,
    boundPort: 18080,
  });
}
{
  // A close and a re-open in the SAME tick: the entry is deleted before the
  // backend is told anything, so the caller that re-creates it under the same
  // key owns what it built. The in-flight close must not take the new entry with
  // it - `forwards.delete` is guarded on the entry still being ours for exactly
  // this interleaving.
  reset([row({ id: "c-bastion" })]);
  const keep = await openForwardForConnection("c-bastion", "10.0.0.9", 22, { localPort: 18443 });
  const first = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, {
    localPort: 18080,
  });
  // Not awaited: the release is synchronous down to the delete, and the close it
  // schedules on the backend runs a microtask later.
  const releasing = closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, first.claim);
  const second = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, {
    localPort: 18080,
  });
  await releasing;
  await settle();
  assert(second.claim !== first.claim, "the re-open built a new entry");
  const third = await openForwardForConnection("c-bastion", "10.0.0.9", 5432, {
    localPort: 18080,
  });
  check("which survived the close that was already in flight", third.claim, second.claim);
  check("so a third caller reuses it instead of rebinding", countOf("ssh_forward_open"), 3);

  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, second.claim);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 5432, 18080, third.claim);
  await closeForwardForConnection("c-bastion", "10.0.0.9", 22, 18443, keep.claim);
  await settle();
  check("and every listener is closed once", countOf("ssh_forward_close"), 3);
}
{
  // The release WAITS for the backend, rather than firing the close and
  // resolving on the spot. `ssh_forward_close` is keyed by bound port with no
  // generation, so a close still in flight names whatever is listening on that
  // port - a re-open's brand-new listener included. A Stop that resolved before
  // the backend heard it, followed by a Start on the same pinned port, is
  // therefore "Start silently does nothing every other time".
  //
  // Every fixture above closes a forward whose open has already RESOLVED, and
  // for those the fire-and-forget form is INDISTINGUISHABLE from this one: its
  // `.then` callback is queued on an already-settled promise, so it runs before
  // the caller's own `await` resumes and the count has arrived either way. What
  // separates them is a stop while the dial is still IN FLIGHT - which is the
  // honest reading of the port's lifetime, since the port is not free until the
  // open that binds it has finished.
  reset([row({ id: "c-bastion" }), row({ id: "c-parked" })]);
  // A claim only ever comes out of a RESOLVED `SshForward`, so an entry whose
  // open is still parked has none that a caller could be holding. Claims are
  // monotonic and never reused (`tunnel.ts:229-231`), so the entry built next
  // carries this one's plus one - which is how this fixture can name an entry it
  // cannot await. The page reaches the same state legitimately: its Start
  // publishes nothing until the open resolves, and its Stop then finds no claim
  // recorded at all.
  const probe = await openForwardForConnection("c-bastion", "10.0.0.9", 22, { localPort: 18443 });
  autoAnswerOpen = false;
  const opening = openForwardForConnection("c-parked", "10.0.0.9", 5432, { localPort: 18080 });
  await settle();
  check("a second bastion's dial is parked mid-handshake", parkedOpens.length, 2);

  const stopping = closeForwardForConnection("c-parked", "10.0.0.9", 5432, 18080, probe.claim + 1);
  // The parked handshake finishes, the way it does when the user finally answers
  // a host-key question - or when a teardown abandons it and the dial fails.
  const parkedSession = nextSessionId++;
  parkedOpens[1].resolve(parkedSession);
  await stopping;
  // No `settle()` here on purpose: a settle would let the fire-and-forget form's
  // microtask land too, and the claim is about WHEN this call resolves.
  check("the close is awaited, not fired and forgotten", countOf("ssh_forward_close"), 1);
  check("naming the port the parked open went on to bind", lastOf("ssh_forward_close")?.args, {
    id: parkedSession,
    boundPort: 18080,
  });

  // The abandoned Start still resolves - it bound its port before the release
  // reached it - and its claim now names an entry nobody holds, which is
  // exactly why the page's Start hands it straight back.
  const late = await opening;
  check(
    "the open it was racing still resolves",
    [late.localPort, late.claim],
    [18080, probe.claim + 1],
  );
  await settle();
  check("and the abandoned dial's session is closed with it", countOf("ssh_close"), 1);

  await closeForwardForConnection("c-bastion", "10.0.0.9", 22, 18443, probe.claim);
  await settle();
  check("the other bastion closes on its own release", countOf("ssh_close"), 2);
}

// ---------------------------------------------------------------------------
console.log("\n[reuse] a second consumer of the SAME target takes its own reference");
// The defect this replaces: reuse returned a port without incrementing, so the
// first close tore the session out from under the second consumer.
{
  reset([row({ id: "c-bastion" })]);
  const first = await openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  const second = await openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  check("the port is reused, not rebound", countOf("ssh_forward_open"), 1);
  check("both consumers get the same forward", first, second);

  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, first.claim);
  await settle();
  check("the first consumer letting go leaves the session up", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, second.claim);
  await settle();
  check("the second one closes it", countOf("ssh_close"), 1);

  // Over-release is the mirror image of the same bug: a stray extra close must
  // not spend a reference this target does not hold.
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, second.claim);
  await closeForwardForConnection("c-bastion", "never.opened", 3389, 0, second.claim);
  await settle();
  check("releasing more than was taken closes nothing extra", countOf("ssh_close"), 1);
}

// ---------------------------------------------------------------------------
console.log("\n[reincarnation] a stale release cannot spend a NEW entry's reference");
// The over-release above is the SPENT case, which the refs-at-zero guard
// catches. This is the re-created one, which it cannot: `dropSession` deletes
// both entries when the bastion dies, and the next consumer of the same target
// builds fresh ones under the same key.
{
  reset([row({ id: "c-bastion" })]);
  const paneA = await openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  check("pane A dials", countOf("ssh_open"), 1);

  // The bastion drops on its own: `onExit` fires and `dropSession` clears both
  // maps. Pane A is told nothing - its RDP session is still riding the dead
  // forward, and a parked TCP connection only fails on a keepalive, so its own
  // `disconnected` can lag by a long way.
  emitOn(parkedOpens[0], { type: "exit", code: 255 });
  await settle();

  // Pane B opens the same target (or the user hits Reconnect): fresh session,
  // fresh forward, SAME key.
  const paneB = await openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  check("pane B gets a second session, not the dead one", countOf("ssh_open"), 2);
  assert(paneA.claim !== paneB.claim, "and a claim of its own, because it is a different entry");

  // Pane A's teardown finally fires. Keyed by target this found pane B's entry
  // at one reference, decremented it to zero and closed pane B's bastion out
  // from under it - a black pane for the survivor.
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, paneA.claim);
  await settle();
  check("pane A's late release closes nothing", countOf("ssh_close"), 0);
  // Nor does a token that names no entry at all.
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, -1);
  await settle();
  check("and neither does a claim from nowhere", countOf("ssh_close"), 0);

  // The guard must not have simply disabled releasing.
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, paneB.claim);
  await settle();
  check("pane B's own release still closes its session", countOf("ssh_close"), 1);
}

// ---------------------------------------------------------------------------
console.log("\n[concurrency] two connects in one tick share one dial");
{
  reset([row({ id: "c-bastion" })]);
  autoAnswerOpen = false;
  const first = openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  const second = openForwardForConnection("c-bastion", "10.10.11.30", 3389);
  await settle();
  check("only one dial is in flight", parkedOpens.length, 1);
  parkedOpens[0].resolve(nextSessionId++);
  const [a, b] = await Promise.all([first, second]);
  check(
    "both rode the same session",
    [countOf("ssh_open"), a.sessionId === b.sessionId],
    [1, true],
  );

  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, a.claim);
  check("and one of them letting go does not close it", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.10.11.30", 3389, 0, b.claim);
  await settle();
  check("the second does", countOf("ssh_close"), 1);
}
{
  // Same tick, same TARGET: two panes on one host behind one bastion, restored
  // together. Both must land on one bound port and one session, and both
  // references must be releasable - the failure mode being one port bound twice
  // and a map entry that replaces the other consumer's, so its release finds
  // nothing and the session is never closed.
  reset([row({ id: "c-bastion" })]);
  autoAnswerOpen = false;
  const first = openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  const second = openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  await settle();
  parkedOpens[0].resolve(nextSessionId++);
  const [a, b] = await Promise.all([first, second]);
  check(
    "one dial, one bind, one port",
    [countOf("ssh_open"), countOf("ssh_forward_open"), a.localPort === b.localPort],
    [1, 1, true],
  );

  check("and one claim, because it is one entry", a.claim, b.claim);
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, a.claim);
  await settle();
  check("the first release leaves it up", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389, 0, b.claim);
  await settle();
  check("and the second one closes it - neither reference was lost", countOf("ssh_close"), 1);
}

// ---------------------------------------------------------------------------
console.log("\n[trust] an unverified bastion refuses by default");
{
  reset([row({ id: "c-nopin", name: "jump box", lastFingerprint: undefined })]);
  let message = "";
  await openForwardForConnection("c-nopin", "10.10.11.26", 3389).catch((e) => {
    message = e instanceof Error ? e.message : String(e);
  });
  assert(message.includes("no verified host key yet"), "it refuses, with the reason");
  assert(message.includes("jump box"), "and names the host by its saved name");
  check("nothing was dialled", countOf("ssh_open"), 0);
}
{
  // A pinned target reached through an UNPINNED jump host is the same hazard one
  // hop further out: `resolveJumpHops` would send no expected fingerprint for
  // that hop, the backend would raise a prompt, and a caller that cannot show
  // one leaves it parked for the full confirm timeout.
  reset([
    row({ id: "c-target", proxyJumpId: "c-hop" }),
    row({ id: "c-hop", name: "entry", lastFingerprint: undefined }),
  ]);
  let message = "";
  await openForwardForConnection("c-target", "10.10.11.26", 3389).catch((e) => {
    message = e instanceof Error ? e.message : String(e);
  });
  assert(message.includes("entry"), "an unpinned JUMP host refuses too, naming the hop");
  check("and still nothing was dialled", countOf("ssh_open"), 0);
}

console.log("\n[trust] a caller that can ask gets the prompt, and the pin lands");
{
  reset([row({ id: "c-nopin", lastFingerprint: undefined })]);
  autoAnswerOpen = false;
  const seen: string[] = [];
  const opening = openForwardForConnection("c-nopin", "10.10.11.26", 3389, {
    promptForHostKey: true,
    onHostKeyPrompt: (id) => seen.push(id),
  });
  await settle();
  check("it dials", parkedOpens.length, 1);
  check(
    "with no expected fingerprint, so the backend asks instead of failing",
    parkedOpens[0].input.expectedFingerprint,
    null,
  );

  // The backend raises the question mid-handshake, before any credential.
  emitOn(parkedOpens[0], {
    type: "hostKeyPrompt",
    promptId: "hk-1",
    fingerprint: "SHA256:fresh",
    host: "c-nopin.example.com",
  });
  check("the shared dialog queue has it", useHostKeyPrompt.getState().queue.length, 1);
  check("and the caller was told the id, so a teardown can answer it", seen, ["hk-1"]);

  useHostKeyPrompt.getState().resolve("hk-1", true);
  await settle();
  check("the backend hears the answer", lastOf("ssh_confirm_host_key")?.args, {
    promptId: "hk-1",
    accept: true,
  });
  check(
    "and trusting it pins the key on the saved row",
    sshRows.find((r) => r.id === "c-nopin")?.lastFingerprint,
    "SHA256:fresh",
  );

  parkedOpens[0].resolve(nextSessionId++);
  const forward = await opening;
  assert(forward.localPort > 0, "the forward then opens as usual");
  await closeForwardForConnection("c-nopin", "10.10.11.26", 3389, 0, forward.claim);
  await settle();
  check("and releases normally", countOf("ssh_close"), 1);
}
{
  // Rejecting must leave nothing behind: no half-registered session, and the
  // next attempt dials again rather than handing back a dead one.
  reset([row({ id: "c-nopin", lastFingerprint: undefined })]);
  autoAnswerOpen = false;
  const opening = openForwardForConnection("c-nopin", "10.10.11.26", 3389, {
    promptForHostKey: true,
  });
  await settle();
  parkedOpens[0].reject(new Error("ssh: host key rejected"));
  let message = "";
  await opening.catch((e) => {
    message = e instanceof Error ? e.message : String(e);
  });
  assert(message.includes("rejected"), "the caller sees the rejection");
  check("no forward was bound", countOf("ssh_forward_open"), 0);

  autoAnswerOpen = true;
  const retry = await openForwardForConnection("c-nopin", "10.10.11.26", 3389, {
    promptForHostKey: true,
  });
  check("and the next attempt dials a fresh session", countOf("ssh_open"), 2);
  await closeForwardForConnection("c-nopin", "10.10.11.26", 3389, 0, retry.claim);
}

console.log("\n[trust] a caller that JOINS a dial learns its prompt ids too");
{
  // A DIFFERENT target, so the joiner re-enters `sessionFor` and takes its reuse
  // branch. The question is already on screen when it arrives, which is the
  // workspace-restore shape: the second pane's effect runs a tick later.
  reset([row({ id: "c-nopin", lastFingerprint: undefined })]);
  autoAnswerOpen = false;
  const firstSeen: string[] = [];
  const joinerSeen: string[] = [];
  const lateSeen: string[] = [];
  const first = openForwardForConnection("c-nopin", "10.10.11.26", 3389, {
    promptForHostKey: true,
    onHostKeyPrompt: (id) => firstSeen.push(id),
  });
  await settle();
  emitOn(parkedOpens[0], {
    type: "hostKeyPrompt",
    promptId: "hk-join",
    fingerprint: "SHA256:fresh",
    host: "c-nopin.example.com",
  });
  check("the caller that started the dial hears it", firstSeen, ["hk-join"]);

  const joiner = openForwardForConnection("c-nopin", "10.10.11.30", 3389, {
    promptForHostKey: true,
    onHostKeyPrompt: (id) => joinerSeen.push(id),
  });
  await settle();
  check("the joiner rides the one dial", parkedOpens.length, 1);
  check("and is caught up on the question already on screen", joinerSeen, ["hk-join"]);
  check(
    "and it is still one prompt in the shared queue, not one per caller",
    useHostKeyPrompt.getState().queue.length,
    1,
  );

  // One answer serves both, because it is one handshake.
  useHostKeyPrompt.getState().resolve("hk-join", true);
  await settle();
  check("answering it pins the key once", countOf("ssh_confirm_host_key"), 1);

  // A caller arriving AFTER the answer is not handed a settled question: it has
  // nothing to abandon, and the id would read as though it could undo a
  // decision that is already made.
  const late = openForwardForConnection("c-nopin", "10.10.11.31", 3389, {
    promptForHostKey: true,
    onHostKeyPrompt: (id) => lateSeen.push(id),
  });
  await settle();
  check("a caller joining after the answer is told nothing", lateSeen, []);

  parkedOpens[0].resolve(nextSessionId++);
  const [a, b, c] = await Promise.all([first, joiner, late]);
  check(
    "all three rode one session",
    [countOf("ssh_open"), a.sessionId === b.sessionId, b.sessionId === c.sessionId],
    [1, true, true],
  );
  await closeForwardForConnection("c-nopin", "10.10.11.26", 3389, 0, a.claim);
  await closeForwardForConnection("c-nopin", "10.10.11.30", 3389, 0, b.claim);
  check("and it survives until the last of them lets go", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-nopin", "10.10.11.31", 3389, 0, c.claim);
  await settle();
  check("then closes", countOf("ssh_close"), 1);
}
{
  // The SAME target, which reuses the forward and never reaches `sessionFor` -
  // the commonest joiner there is, and the one that would otherwise learn no
  // prompt ids at all.
  reset([row({ id: "c-nopin", lastFingerprint: undefined })]);
  autoAnswerOpen = false;
  const seenA: string[] = [];
  const seenB: string[] = [];
  const paneA = openForwardForConnection("c-nopin", "10.10.11.26", 3389, {
    promptForHostKey: true,
    onHostKeyPrompt: (id) => seenA.push(id),
  });
  const paneB = openForwardForConnection("c-nopin", "10.10.11.26", 3389, {
    promptForHostKey: true,
    onHostKeyPrompt: (id) => seenB.push(id),
  });
  await settle();
  check("one dial for both panes", parkedOpens.length, 1);
  emitOn(parkedOpens[0], {
    type: "hostKeyPrompt",
    promptId: "hk-same",
    fingerprint: "SHA256:fresh",
    host: "c-nopin.example.com",
  });
  check("both panes on one target hear the question", [seenA, seenB], [["hk-same"], ["hk-same"]]);

  useHostKeyPrompt.getState().resolve("hk-same", true);
  await settle();
  parkedOpens[0].resolve(nextSessionId++);
  const [a, b] = await Promise.all([paneA, paneB]);
  await closeForwardForConnection("c-nopin", "10.10.11.26", 3389, 0, a.claim);
  await closeForwardForConnection("c-nopin", "10.10.11.26", 3389, 0, b.claim);
  await settle();
  check("and both references release normally", countOf("ssh_close"), 1);
}
{
  // The accepted consequence, pinned so it stays a decision rather than a
  // surprise: ANY caller riding one dial can fail it for all of them by
  // abandoning, because a rejected host key aborts the shared handshake. That
  // is the fail-safe direction - see `SshForwardOptions.onHostKeyPrompt` for why
  // the alternative cannot be built on the refcount.
  reset([row({ id: "c-nopin", lastFingerprint: undefined })]);
  autoAnswerOpen = false;
  const joinerSeen: string[] = [];
  const first = openForwardForConnection("c-nopin", "10.10.11.26", 3389, {
    promptForHostKey: true,
  });
  const joiner = openForwardForConnection("c-nopin", "10.10.11.30", 3389, {
    promptForHostKey: true,
    onHostKeyPrompt: (id) => joinerSeen.push(id),
  });
  await settle();
  emitOn(parkedOpens[0], {
    type: "hostKeyPrompt",
    promptId: "hk-abandon",
    fingerprint: "SHA256:fresh",
    host: "c-nopin.example.com",
  });
  check("the joiner has an id to abandon", joinerSeen, ["hk-abandon"]);

  // The joiner's teardown, with the question still up. Before the fix it had
  // nothing to abandon here, so the leak could only ever be closed by the other
  // caller.
  useHostKeyPrompt.getState().abandon("hk-abandon");
  await settle();
  check("the backend is told to reject", lastOf("ssh_confirm_host_key")?.args, {
    promptId: "hk-abandon",
    accept: false,
  });
  check("and the prompt leaves the shared queue", useHostKeyPrompt.getState().queue.length, 0);

  // Which is the backend aborting the handshake both callers were riding.
  parkedOpens[0].reject(new Error("ssh: host key rejected"));
  const messages: string[] = [];
  for (const p of [first, joiner]) {
    await p.catch((e) => messages.push(e instanceof Error ? e.message : String(e)));
  }
  check("BOTH dials fail, deliberately", messages, [
    "ssh: host key rejected",
    "ssh: host key rejected",
  ]);
  check("nothing was bound", countOf("ssh_forward_open"), 0);

  // And nothing is left behind, so Reconnect - which is what the cost of the
  // rejection actually is - dials afresh and asks again.
  autoAnswerOpen = true;
  const again = await openForwardForConnection("c-nopin", "10.10.11.26", 3389, {
    promptForHostKey: true,
  });
  check("a retry dials a fresh session", countOf("ssh_open"), 2);
  await closeForwardForConnection("c-nopin", "10.10.11.26", 3389, 0, again.claim);
  await settle();
  check("and releases normally", countOf("ssh_close"), 1);
}

// ---------------------------------------------------------------------------
console.log("\n[dial] the tunnel changes the address and nothing else");

const rdpRow: RdpHostFixture = {
  id: "r-win",
  name: "win-build-01",
  host: "10.10.11.26",
  port: 3389,
  protocol: "rdp",
  credential: {
    kind: "inline",
    hostId: "r-win",
    username: "Administrator",
    domain: "CORP",
    hasPassword: true,
  },
  desktopWidth: 1280,
  desktopHeight: 800,
  sizeMode: "preset",
  certFingerprint: "49:67:09:05",
};

{
  const direct = await rdpOpenInput(rdpRow, { host: rdpRow.host, port: rdpRow.port });
  const tunnelled = await rdpOpenInput(rdpRow, { host: "127.0.0.1", port: 45123 });
  check("the address differs", [tunnelled.host, tunnelled.port], ["127.0.0.1", 45123]);
  check(
    "the pinned certificate does not",
    [direct.expectedCertFingerprint, tunnelled.expectedCertFingerprint],
    ["49:67:09:05", "49:67:09:05"],
  );
  check(
    "and neither does anything else",
    { ...direct, host: "", port: 0 },
    { ...tunnelled, host: "", port: 0 },
  );
  check("the password travels as a keychain reference, never a value", direct.credential, {
    kind: "keychain",
    service: "tervia-hosts",
    account: "r-win::password",
  });
}

{
  reset([row({ id: "c-bastion" })]);
  const target = await openRdpDialTarget({ host: rdpRow.host, port: rdpRow.port });
  check(
    "a row with no tunnel dials the host itself",
    [target.host, target.port, target.viaTunnel],
    ["10.10.11.26", 3389, false],
  );
  target.release();
  await settle();
  check("and releasing it touches no SSH session", countOf("ssh_open") + countOf("ssh_close"), 0);
}

{
  reset([row({ id: "c-bastion" })]);
  const tunnelled = { ...rdpRow, tunnel: { sshHostId: "c-bastion" } };
  // Two panes on one host through one bastion - the shape the reuse defect
  // broke, seen from the RDP side.
  const one = await openRdpDialTarget(tunnelled);
  const two = await openRdpDialTarget(tunnelled);
  check("both dial loopback", [one.host, two.host], ["127.0.0.1", "127.0.0.1"]);
  check("on the same forward", one.port, two.port);
  check("over one session", countOf("ssh_open"), 1);
  assert(one.viaTunnel && two.viaTunnel, "and both know they are tunnelled");

  // Idempotent release: a pane's teardown fires it without knowing whether an
  // error path already did, and a second release would spend the OTHER pane's
  // reference.
  one.release();
  one.release();
  one.release();
  await settle();
  check("releasing one pane, twice over, leaves the other's tunnel up", countOf("ssh_close"), 0);
  two.release();
  await settle();
  check("the last pane out closes the session", countOf("ssh_close"), 1);
}

console.log(failed === 0 ? "\nAll rdp-tunnel checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
