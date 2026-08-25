/**
 * Self-check for the three things in the RDP frontend that must not outlive
 * their owner: a trust prompt, a held key, and a Test probe.
 * Run: `npx tsx scripts/rdp-lifetime-verify.ts`.
 *
 * Source text, not imports, and for the same reason `toast-verify.ts` gives:
 * these live inside a React component's effects and event handlers, and there is
 * no DOM or renderer in this suite to drive them through. What is checkable
 * without one is the STRUCTURE, and structure is exactly what all three
 * regressions were - a branch that returned instead of answering, a set that was
 * not in a guard, a state write with no staleness check. Each check below names
 * the failure it exists to catch, and each one is verified to fail when the
 * corresponding line is removed.
 *
 * 1. A CERTIFICATE PROMPT THAT LANDS AFTER THE PANE IS GONE IS REJECTED. The
 *    pane's teardown answers the id it recorded, and the id is recorded INSIDE
 *    the prompt handler - so a handler that returns early on `!alive` records
 *    nothing and the teardown has nothing to answer. The window is the TCP
 *    connect plus the TLS handshake, and closing a tab that says "Connecting…"
 *    is an ordinary thing to do. Behind an unanswered prompt the backend's
 *    verifier is parked on its full confirm timeout, holding the socket, the
 *    in-flight handshake and - because it blocks - a displaced runtime thread,
 *    once per open/close cycle. `rdp_open` has not returned, so no session id
 *    exists and `rdp_close` cannot help: the rejection is the only way out.
 *
 * 2. EVERY HELD SET IS COVERED BY `releaseAll`. A key with no scancode goes out
 *    as `unicodeDown`, so it never reaches `heldKeys`; while that was the only
 *    record, `releaseAll` saw nothing held on blur and sent no marker at all.
 *    The stranded character then stays pressed in the backend's own record, and
 *    since `Database::apply` suppresses no-op transitions its next real press
 *    emits nothing either - a key gone dead rather than merely stuck. So the
 *    check is not "is there a unicode set" but the general form: every held set
 *    the pane declares is in `releaseAll`'s guard, cleared by it, and cleared
 *    when a redial resets state - which also fails for a FOURTH set added later
 *    and forgotten.
 *
 * 3. A TEST PROBE CANNOT WRITE TO A ROW IT NO LONGER BELONGS TO. The merged host
 *    editor (`HostEditorDialog`, 6d - this used to be `RdpConnectionDialog`) is
 *    mounted persistently once latched and the trust prompt is global, so
 *    closing the dialog neither cancels a probe nor hides its question: row A ->
 *    Test -> cancel -> open row B -> answer, and an ungated
 *    `setPinnedFingerprint` writes A's certificate (or SSH host key) into B's
 *    form state, which Save then persists onto B. It fails closed (B's next
 *    connect aborts as a mismatch) but it is a pinned key on a row the user
 *    never tested. The merge widened this from an RDP-only check to both
 *    protocols, since one `runTest` and one `onTrusted` now serve them both.
 *
 * 4. THE `pagehide` BACKSTOP ANSWERS BOTH PROTOCOLS. `HostKeyPromptDialog` is
 *    shared, so its backstop fires for an SSH host key as well as an RDP
 *    certificate. That is deliberate - `ssh_open` waits on the same 120 seconds
 *    holding the same mid-handshake socket - and it is pinned here because it
 *    reads like an accident of sharing, so the obvious "tidy-up" is to scope it
 *    back to certificates. This check makes that argue with the comment first.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

/**
 * The source between two anchors, or "" if either is missing.
 *
 * Anchored on code rather than line numbers so an edit above does not move the
 * region, and the "region was found" check below is what catches an anchor that
 * has been renamed out from under this file - otherwise every check over an
 * empty string would pass for the wrong reason.
 */
function between(src: string, from: string, to: string): string {
  const start = src.indexOf(from);
  if (start < 0) return "";
  const end = src.indexOf(to, start + from.length);
  if (end < 0) return "";
  return src.slice(start, end);
}

const paneSrc = read("src/modules/rdp/RdpPane.tsx");
const editorSrc = read("src/modules/hosts/HostEditorDialog.tsx");
const promptDialogSrc = read("src/modules/ssh/HostKeyPromptDialog.tsx");

// ---------------------------------------------------------------------------
console.log("[1] a certificate prompt raised after the teardown is ANSWERED");
{
  const handler = between(paneSrc, "onCertPrompt: (prompt) => {", "onResize:");
  check("the cert-prompt handler was found", handler.length > 100, handler.length);

  const guard = handler.indexOf("if (!alive)");
  const records = handler.indexOf("promptId = prompt.promptId");
  check("it guards on liveness", guard >= 0);
  check("and records the id for the teardown to answer", records > guard, [guard, records]);

  // The whole finding in one assertion: the liveness branch has to answer,
  // because it runs BEFORE the id exists anywhere the teardown can reach.
  const branch = handler.slice(guard, records < 0 ? undefined : records);
  check(
    "the liveness branch rejects the prompt itself",
    /confirmRdpCert\(\s*prompt\.promptId,\s*false\s*\)/.test(branch),
    branch.trim().slice(-120),
  );
  check(
    "and does not merely return, which would drop it with nobody to answer",
    !/if \(!alive\) return;/.test(handler),
  );
}
{
  // The other half of the invariant, unchanged by this fix and pinned so it
  // stays: a prompt the pane DID record is answered on the way out, and the
  // tunnel's host-key questions with it.
  const teardown = between(paneSrc, "return () => {\n      alive = false;", "}, [connectionId");
  check("the session effect's teardown was found", teardown.length > 100, teardown.length);
  check(
    "a recorded certificate prompt is abandoned on the way out",
    /if \(promptId\) useHostKeyPrompt\.getState\(\)\.abandon\(promptId\);/.test(teardown),
  );
  check(
    "and so is every tunnel host-key prompt this attempt raised",
    /for \(const id of sshPromptIds\) useHostKeyPrompt\.getState\(\)\.abandon\(id\);/.test(
      teardown,
    ),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[2] every held set the pane keeps is released on blur");
{
  // Whatever they are called and however many there are. A fourth set added
  // later and left out of any of the three places below fails this.
  const held = [...paneSrc.matchAll(/const (held\w+) = useRef</g)].map((m) => m[1]);
  check("the pane's held sets were found", held.length >= 3, held);
  check("including one for keys with no scancode", held.includes("heldUnicode"), held);

  const releaseAll = between(
    paneSrc,
    "const releaseAll = useCallback(() => {",
    "}, [queueInputNow]);",
  );
  check("releaseAll was found", releaseAll.length > 50, releaseAll.length);
  // The early return is the bug's location: it decides whether the marker is
  // sent at all, and a set missing from it is a set that cannot trigger one.
  const guard = between(releaseAll, "if (", "{\n      return;");
  check("its early return guard was found", guard.length > 20, guard);
  for (const set of held) {
    check(`${set} is in the guard, so holding only it still sends the marker`, guard.includes(set));
    check(`${set} is cleared by releaseAll`, releaseAll.includes(`${set}.current.clear()`));
  }

  // A redial starts from nothing held: the server has a fresh session and the
  // old record would make the first release of a carried-over key a no-op.
  const reset = between(paneSrc, 'setStatus({ kind: "connecting" });', "void (async () => {");
  check("the redial reset was found", reset.length > 50, reset.length);
  for (const set of held) {
    check(`${set} is cleared when the pane redials`, reset.includes(`${set}.current.clear()`));
  }

  // Forward-looking: a new "down" input kind must record what it pressed, or
  // `releaseAll` cannot know about it however many sets exist.
  //
  // Ctrl+Alt+Del is the one exemption, and a real one rather than an oversight:
  // it synthesises its own matching ups in the same batch, so nothing is ever
  // left held for a blur to release. `rdp-frame-verify.ts` is where that pairing
  // is asserted ("released in reverse", "nothing is left held"), so skipping it
  // here does not leave it unchecked.
  const cadFrom = paneSrc.indexOf("const sendCtrlAltDel = useCallback(");
  const cadTo = paneSrc.indexOf("}, [queueInput]);", cadFrom);
  check(
    "the Ctrl+Alt+Del synthesiser was found, so the exemption is real",
    cadFrom >= 0 && cadTo > cadFrom,
    [cadFrom, cadTo],
  );
  const downKinds = [...paneSrc.matchAll(/kind: "(\w+Down)"/g)]
    .map((m) => ({ kind: m[1], at: m.index ?? 0 }))
    .filter(({ at }) => at < cadFrom || at > cadTo);
  check(
    "the pane's press-side input kinds were found",
    downKinds.length >= 3,
    downKinds.map((d) => d.kind),
  );
  for (const { kind, at } of downKinds) {
    // Looking backwards, because the record is taken before the event is
    // queued - the order the handlers are written in.
    const before = paneSrc.slice(Math.max(0, at - 220), at);
    check(
      `${kind} records what it pressed in a held set`,
      /held\w+\.current\.add\(/.test(before),
      before.trim().slice(-80),
    );
  }
}

// ---------------------------------------------------------------------------
console.log("\n[3] a Test probe cannot write to a row it no longer belongs to");
{
  check(
    "the editor tracks the target it is showing right now",
    /applied\.current = token;/.test(editorSrc),
  );

  const runTest = between(editorSrc, "const runTest = async () => {", "const save = async () => {");
  check("runTest was found", runTest.length > 500, runTest.length);
  check("a probe captures the token it started on", /const probeToken = token;/.test(runTest));
  check(
    "and compares it against the target on screen, not against its own capture",
    /applied\.current === probeToken/.test(runTest),
  );

  /**
   * Is this write gated by its OWN immediately-preceding `onProbeRow()` guard -
   * same statement, not merely "somewhere earlier in the function"? The naive
   * "look back N chars" check false-positived here: `onTrusted`'s two writes
   * sit right next to each other, so a wide-enough lookback from the SECOND
   * (deliberately ungated) one still sees the FIRST write's guard and calls it
   * gated. Stopping at the nearest statement terminator is what tells them
   * apart.
   */
  const gated = (needle: string): boolean => {
    const at = runTest.indexOf(needle);
    if (at < 0) return false;
    const guardAt = runTest.lastIndexOf("onProbeRow()", at);
    if (guardAt < 0) return false;
    return !runTest.slice(guardAt, at).includes(";");
  };
  check(
    "accepting a certificate or host key writes the form's pin only while the target matches",
    gated("setPinnedFingerprint(fingerprint)"),
  );
  // The saved row is the opposite case and must NOT be gated: `probeHostId` is
  // the row that was tested, so the pin belongs there however long the answer
  // took.
  check(
    "but the SAVED row is pinned unconditionally, since that is the row tested",
    !gated("pinFingerprint(probeHostId, fingerprint)"),
  );
  check("a successful result is gated", gated('kind: "ok"'));
  check("and so is a failure", gated('kind: "fail"'));
  // The synchronous one at the top of the probe is deliberately not gated: it
  // runs before any await, so it cannot be stale.
  check(
    "the probe's own 'running' state is not gated, being written before any await",
    !gated('setTest({ kind: "running" })'),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[4] the pagehide backstop answers BOTH protocols' prompts");
{
  const backstop = between(promptDialogSrc, "const abandonAll = () => {", "};");
  check("the backstop was found", backstop.length > 50, backstop.length);
  check(
    "it walks the whole queue",
    /for \(const p of \[\.\.\.pending\]\) abandon\(p\.promptId\);/.test(backstop),
  );
  // The decision this pins: an SSH host key is answered on the way out too, not
  // only an RDP certificate. Scoping it to `certificate` would leave `ssh_open`
  // parked on its own 120-second wait for the same reason, so a later narrowing
  // has to argue with the comment above the effect rather than slip through.
  check(
    "and does not filter on the field that distinguishes the two",
    !backstop.includes("certificate"),
    backstop.trim(),
  );
  check(
    "on pagehide rather than this component's unmount, which live panes survive",
    /addEventListener\("pagehide", abandonAll\)/.test(promptDialogSrc) &&
      !/return \(\) => abandonAll\(\)/.test(promptDialogSrc),
  );
}

console.log(failed === 0 ? "\nAll rdp-lifetime checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
