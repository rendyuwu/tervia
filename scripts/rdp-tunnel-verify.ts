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
 */

export {};

// ---------------------------------------------------------------------------
// Stand-in for the Tauri IPC bridge `@tauri-apps/api` calls into.
// ---------------------------------------------------------------------------

type Call = { cmd: string; args: Record<string, unknown> };
const calls: Call[] = [];
const callbacks = new Map<number, (payload: unknown) => void>();
let nextCallbackId = 1;

/** The SSH connection store's contents. Mutable: pinning a fingerprint writes
 *  through this, which is how prompt attribution is observed. */
type Row = Record<string, unknown> & { id: string };
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

async function handleInvoke(cmd: string, args: Record<string, unknown>): Promise<unknown> {
  calls.push({ cmd, args });
  switch (cmd) {
    // The connection store. One key ("connections"), so one answer.
    case "plugin:store|load":
    case "plugin:store|get_store":
      return 1;
    case "plugin:store|get":
      return [sshRows, true];
    case "plugin:store|set":
      sshRows = args.value as Row[];
      return undefined;
    case "plugin:store|save":
    case "plugin:event|emit":
      return undefined;
    case "secrets_get":
      return secrets[args.account as string] ?? null;
    case "ssh_open": {
      const channelId = (args.onEvent as { id: number }).id;
      const input = args.input as Record<string, unknown>;
      return await new Promise<number>((resolve, reject) => {
        parkedOpens.push({ input, channelId, resolve, reject });
        if (autoAnswerOpen) resolve(nextSessionId++);
      });
    }
    case "ssh_forward_open":
      return nextLocalPort++;
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
type RdpConnection = Parameters<typeof rdpOpenInput>[0];

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

function countOf(cmd: string): number {
  return calls.filter((c) => c.cmd === cmd).length;
}
function lastOf(cmd: string): Call | undefined {
  return [...calls].reverse().find((c) => c.cmd === cmd);
}

function row(over: Partial<Row> & { id: string }): Row {
  return {
    name: over.id,
    host: `${over.id}.example.com`,
    port: 22,
    user: "ubuntu",
    authMode: "agent",
    hasPassword: false,
    hasPrivateKey: false,
    hasKeyPassphrase: false,
    lastFingerprint: `SHA256:pin-${over.id}`,
    ...over,
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
}

// ---------------------------------------------------------------------------
console.log("[auth] the call site that had never executed");
// `tunnel.ts:61`'s `authFields(conn.authMode, secrets)`: dead code until now, on
// the path that reads private keys out of the keychain.
{
  reset([row({ id: "c-pass", authMode: "password", hasPassword: true })]);
  secrets["c-pass::password"] = "s3cret";
  await openForwardForConnection("c-pass", "10.0.0.9", 3389);
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
  await closeForwardForConnection("c-pass", "10.0.0.9", 3389);
}
{
  reset([row({ id: "c-key", authMode: "key", hasPrivateKey: true, hasKeyPassphrase: true })]);
  secrets["c-key::privateKey"] = "-----BEGIN OPENSSH PRIVATE KEY-----";
  secrets["c-key::keyPassphrase"] = "hunter2";
  await openForwardForConnection("c-key", "10.0.0.9", 3389);
  const input = lastOf("ssh_open")?.args.input as Record<string, unknown>;
  check(
    "a key connection sends key and passphrase",
    [input.privateKey, input.privateKeyPassphrase],
    ["-----BEGIN OPENSSH PRIVATE KEY-----", "hunter2"],
  );
  check("and no password", input.password, null);
  await closeForwardForConnection("c-key", "10.0.0.9", 3389);
}
{
  reset([row({ id: "c-agent" })]);
  await openForwardForConnection("c-agent", "10.0.0.9", 3389);
  const input = lastOf("ssh_open")?.args.input as Record<string, unknown>;
  check(
    "an agent connection asks for the agent and nothing else",
    [input.useAgent, input.password, input.privateKey],
    [true, null, null],
  );
  await closeForwardForConnection("c-agent", "10.0.0.9", 3389);
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

  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389);
  check("releasing one forward does not close the session", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.10.11.30", 5432);
  await settle();
  check("the last one does", countOf("ssh_close"), 1);

  // And the session is forgotten with it, so the next consumer dials afresh
  // rather than being handed a port nothing is listening on.
  await openForwardForConnection("c-bastion", "10.10.11.26", 3389);
  check("a later consumer opens a new session", countOf("ssh_open"), 2);
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389);
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

  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389);
  await settle();
  check("the first consumer letting go leaves the session up", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389);
  await settle();
  check("the second one closes it", countOf("ssh_close"), 1);

  // Over-release is the mirror image of the same bug: a stray extra close must
  // not spend a reference this target does not hold.
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389);
  await closeForwardForConnection("c-bastion", "never.opened", 3389);
  await settle();
  check("releasing more than was taken closes nothing extra", countOf("ssh_close"), 1);
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

  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389);
  check("and one of them letting go does not close it", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.10.11.30", 3389);
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

  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389);
  await settle();
  check("the first release leaves it up", countOf("ssh_close"), 0);
  await closeForwardForConnection("c-bastion", "10.10.11.26", 3389);
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
  const emit = callbacks.get(parkedOpens[0].channelId)!;
  emit({
    index: 0,
    message: {
      type: "hostKeyPrompt",
      promptId: "hk-1",
      fingerprint: "SHA256:fresh",
      host: "c-nopin.example.com",
    },
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
  await closeForwardForConnection("c-nopin", "10.10.11.26", 3389);
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
  await openForwardForConnection("c-nopin", "10.10.11.26", 3389, { promptForHostKey: true });
  check("and the next attempt dials a fresh session", countOf("ssh_open"), 2);
  await closeForwardForConnection("c-nopin", "10.10.11.26", 3389);
}

// ---------------------------------------------------------------------------
console.log("\n[dial] the tunnel changes the address and nothing else");

const rdpRow: RdpConnection = {
  id: "r-win",
  name: "win-build-01",
  host: "10.10.11.26",
  port: 3389,
  username: "Administrator",
  domain: "CORP",
  desktopWidth: 1280,
  desktopHeight: 800,
  sizeMode: "preset",
  hasPassword: true,
  certFingerprint: "49:67:09:05",
};

{
  const direct = rdpOpenInput(rdpRow, { host: rdpRow.host, port: rdpRow.port });
  const tunnelled = rdpOpenInput(rdpRow, { host: "127.0.0.1", port: 45123 });
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
    service: "tervia-rdp",
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
  const tunnelled = { ...rdpRow, tunnel: { sshConnectionId: "c-bastion" } };
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
