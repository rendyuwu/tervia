/**
 * Self-check: a connect that failed for a LOCAL reason must not
 * enter the reconnect ladder.
 * Run: `npx tsx scripts/ssh-retry-verify.ts`.
 *
 * The bug: a host saved with no password (a legal state since the save
 * validation was relaxed) was clicked to connect, and the pane spent 1s + 3s + 7s
 * failing three more times with the identical message before it would let the
 * user do anything. Nothing about the saved host changes while the pane waits,
 * so every one of those attempts was known-doomed at the moment it was
 * scheduled.
 *
 * This is a DIFFERENT question from `scripts/ssh-exit-verify.ts`'s, and the
 * distinction is the whole point: that file is about a shell channel that
 * existed and then ended, so it flows through `decideSshEnding`. The failure
 * here happens before any channel exists - `openSsh` rejects, `finishSsh` is
 * never called, and `decideSshEnding` never runs. The retry for it is scheduled
 * from the two catch blocks around `openPtyForSession` instead, which is where
 * the fourth category has to be honoured.
 *
 * The same bug had a second half, fixed later: the failure the BACKEND reports.
 * A wrong stored password is refused by the server, and `ssh_open` used to relay
 * that as a bare string - which the classifier files transport by construction,
 * so it too walked 1s + 3s + 7s. `ssh_open` now rejects with `{kind, message}`
 * and `sshConnectErrorFrom` (bridge.ts) turns the kind into the same error TYPES
 * this file already checks, so both halves of the ladder answer one question.
 *
 * What is checked here:
 *   1. `canAuthenticate` - the pre-dial guard, against the same truth table the
 *      backend's `has_credential` is tested with.
 *   2. `classifySshConnectFailure` - structural (an error TYPE), so it cannot
 *      rot the way a list of message prefixes would.
 *   3. `decideSshConnectFailure` - only the transport category reconnects, and
 *      the categories stay DISTINCT.
 *   4. `hostKeyRefused` - an ANSWER decides, and any refusal in a chain counts.
 *   5. `sshConnectErrorFrom` - the wire boundary: each kind becomes the right
 *      error type, an unrecognised rejection passes through IDENTICAL, the end-
 *      to-end verdict is park/park/reconnect, and the two regressions the raw
 *      object caused (`isHostKeyMismatchError` no longer matching,
 *      `[object Object]` / `{"kind":…}` reaching the user) stay closed.
 *   6. Rust/TS parity for the mirrored guard and its wording, and for the set of
 *      connect-error kinds - then, in Rust alone, the kind each connect-path
 *      failure SITE names. That is the only place the choice is actually made,
 *      and nothing else in the tree pins it.
 *   7. Source text, Rust: the Windows ssh-agent fallback marks itself UNPROVEN,
 *      so an absent agent parks on that platform too. Nothing else in the tree
 *      can see that arm - it is `#[cfg(windows)]` and CI runs no Rust tests on
 *      Windows.
 *   8. Source text: the `ssh_open` dial's own rejection is chained through
 *      `sshConnectErrorFrom`, and at both catch sites the park arm lexically
 *      CONTROLS the ladder call - it is a statement of the same block and it
 *      terminates it - and the pre-flight block marks what it throws. Pure
 *      functions that nobody calls fix nothing, and a gate that is merely NEAR
 *      the ladder is not a gate (see the section's own header).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Imported and CALLED, not read as text. `openSsh` cannot be reached from here
// (it invokes a Tauri command), which is the whole reason the wrapping decision
// was extracted into `sshConnectErrorFrom`: the rest of bridge.ts loads under
// plain node, so the boundary can be covered behaviourally instead of by
// matching source against an anchor.
import { describeError } from "../src/lib/describeError";
import {
  HOST_KEY_MISMATCH_PREFIX,
  isHostKeyMismatchError,
  sshConnectErrorFrom,
  type SshConnectErrorKind,
} from "../src/modules/ssh/bridge";
import {
  canAuthenticate,
  classifySshConnectFailure,
  decideSshConnectFailure,
  hostKeyRefused,
  SshAuthRejectedError,
  SshLocalConnectError,
  type SshAuthAttempt,
} from "../src/modules/terminal/lib/ssh-exit-decision";
import { stripCommentsNoJsx } from "./lib/source";
import { scopeOf } from "./lib/scope";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const readRaw = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

// Every source-text read below is comment-free by construction, and not
// optional politeness: a source-text check that
// reads raw text goes GREEN over `// was: decideSshConnectFailure(...)`, so
// deleting the gate and leaving a note behind would read as a pass.
//
// `stripCommentsNoJsx` rather than `stripComments` because neither input is
// JSX - a brace wrapping a block comment here is an object or type literal,
// and the JSX branch would delete it with the code inside. The quote set is
// per language: Rust's `'a` lifetime is not a quote, and treating it as one
// opens a state that never closes and swallows the rest of the line, which for
// `has_credential('a ...)` would hide real code from a check rather than
// reveal it.
const readTs = (rel: string) => stripCommentsNoJsx(readRaw(rel), "\"'`");
const readRust = (rel: string) => stripCommentsNoJsx(readRaw(rel), '"');

let failed = 0;
function assert(cond: boolean, msg: string): void {
  if (cond) console.log(`  ok: ${msg}`);
  else {
    console.error(`  FAIL: ${msg}`);
    failed++;
  }
}

console.log("[canAuthenticate] any one credential is enough to be worth dialling");
for (const [label, attempt] of [
  ["ssh-agent alone", { useAgent: true }],
  ["password alone", { password: "pw" }],
  ["private key alone", { privateKey: "-----BEGIN..." }],
] as [string, SshAuthAttempt][]) {
  assert(canAuthenticate(attempt), `${label} -> dial`);
}

console.log("\n[canAuthenticate] nothing configured is the state that must not dial");
assert(!canAuthenticate({}), "no agent, no password, no key -> refuse before dialling");
assert(
  !canAuthenticate({ useAgent: false }),
  "an explicit useAgent:false with nothing else is still nothing to authenticate with",
);
// `resolveSshAuth` maps an empty secret to `undefined`, never "", so this row is
// about agreeing with the backend rather than about a reachable state: the
// backend's `has_credential` tests presence (`is_some`), so an empty string is
// a credential to SEND and the server decides. Testing emptiness on one side
// only would make the two guards disagree about the same input.
console.log("\n[canAuthenticate] presence, not emptiness - matching the backend guard");
assert(
  canAuthenticate({ password: "" }),
  'password "" is present, so it is dialled (server\'s call)',
);
assert(canAuthenticate({ privateKey: "" }), 'private key "" is present, so it is dialled');

console.log("\n[classifySshConnectFailure] the category rides on the error TYPE, not its wording");
{
  const local = classifySshConnectFailure(new SshLocalConnectError("ssh: no credentials: …"), "m");
  assert(local.kind === "local" && local.message === "m", "SshLocalConnectError -> local");

  // The exact regression a message match would introduce: reword the backend's
  // string, or add a new local failure, and a prefix list silently mis-files it.
  // Here the wording is irrelevant by construction, so prove it: the same text
  // classifies differently depending only on how it was thrown.
  const sameWordsPlainError = classifySshConnectFailure(
    new Error("ssh: no credentials: …"),
    "ssh: no credentials: …",
  );
  assert(
    sameWordsPlainError.kind === "transport",
    "the identical message thrown as a plain Error is NOT local - the type decides, not the text",
  );

  // The third arm, pinned on the CLASSIFICATION and not on the action. Both
  // `local` and `rejected` park, so every action-level assertion in this file
  // stays green if the two wrappers are folded into one arm - and the doc
  // comment on `SshConnectFailure` argues at length that they must not be. This
  // is the only check that notices.
  const refused = classifySshConnectFailure(new SshAuthRejectedError("ssh: auth rejected"), "m");
  assert(
    refused.kind === "rejected" && refused.message === "m",
    "SshAuthRejectedError -> rejected (NOT local - the server's fact, not ours)",
  );
  assert(
    refused.kind !== local.kind,
    "the two wrappers stay DISTINCT classifications, not two spellings of park",
  );
}

console.log("\n[classifySshConnectFailure] anything the frontend did not raise stays transport");
for (const [label, thrown] of [
  ["a plain Error from the bridge", new Error("ssh: connect failed: connection refused")],
  ["a bare string rejection", "ssh: connect to h:22 timed out"],
  ["a non-Error object", { message: "ssh: open tunnel to h:22 failed" }],
  ["null", null],
] as [string, unknown][]) {
  assert(
    classifySshConnectFailure(thrown, "msg").kind === "transport",
    `${label} -> transport (still reconnect-eligible)`,
  );
}

console.log("\n[decideSshConnectFailure] only the transport category enters the ladder");
{
  const parked = decideSshConnectFailure({ kind: "local", message: "cfg" });
  assert(parked.action === "park" && parked.message === "cfg", "local -> park, message preserved");
  const laddered = decideSshConnectFailure({ kind: "transport", message: "drop" });
  assert(
    laddered.action === "reconnect" && laddered.message === "drop",
    "transport -> reconnect, message preserved",
  );
  // The collapse guard, same shape as ssh-exit-verify.ts's: a change that mapped
  // both categories onto one action would leave every assertion above passing
  // for one of them and still reintroduce the bug.
  assert(parked.action !== laddered.action, "the two categories map to two DISTINCT actions");
  const refused = decideSshConnectFailure({ kind: "rejected", message: "no" });
  assert(
    refused.action === "park" && refused.message === "no",
    "rejected -> park, message preserved (the server already answered)",
  );
  assert(
    refused.action !== laddered.action,
    "a server's refusal does NOT map onto the ladder's action",
  );
}

// ============================================================================
// THE WIRE BOUNDARY: `ssh_open` rejects with `{kind, message}`, and exactly one
// function turns that back into an error the rest of the app can classify.
//
// Called, not read. Everything below runs the real `sshConnectErrorFrom` from
// bridge.ts against the real classifier, so a check here fails for the same
// reason the app would misbehave rather than because an anchor moved.

/** One payload per kind, with a message distinct enough that a check cannot
 *  pass by accident on a substring of another. */
const PAYLOADS: { kind: SshConnectErrorKind; message: string }[] = [
  { kind: "config", message: "ssh: no credentials: set use_agent, password, or private_key" },
  { kind: "auth", message: "ssh: authentication rejected" },
  { kind: "transport", message: "ssh: connect to h:22 timed out" },
];

console.log("\n[sshConnectErrorFrom] each kind becomes the error type that decides its fate");
{
  const [config, auth, transport] = PAYLOADS.map((p) => sshConnectErrorFrom(p));

  assert(
    config instanceof SshLocalConnectError && config.message === PAYLOADS[0].message,
    "config -> SshLocalConnectError, message verbatim",
  );
  assert(
    auth instanceof SshAuthRejectedError && auth.message === PAYLOADS[1].message,
    "auth -> SshAuthRejectedError, message verbatim",
  );
  // Neither of the above, spelled out: an `Error` subclass satisfies
  // `instanceof Error`, so "is an Error" alone would pass for all three and
  // prove nothing about the one kind that must keep laddering.
  assert(
    transport instanceof Error &&
      !(transport instanceof SshLocalConnectError) &&
      !(transport instanceof SshAuthRejectedError) &&
      (transport as Error).message === PAYLOADS[2].message,
    "transport -> a plain Error that is NEITHER wrapper, message verbatim",
  );

  // The message is taken from the payload's own field, not from stringifying
  // it. `String({kind,message})` is `[object Object]`, which is the exact text
  // that used to reach the user.
  for (const e of [config, auth, transport]) {
    assert(
      !/\[object Object\]/.test((e as Error).message),
      `the wrapper's message is the payload's, not a stringified object (${(e as Error).name})`,
    );
  }
}

console.log("\n[sshConnectErrorFrom] anything it does not recognise comes back IDENTICAL");
{
  // The rollback property. A backend older than this change, a Tauri framework
  // rejection, or a kind added on the Rust side and not here must not become a
  // park - it must reach the classifier as something nobody attributed, be
  // filed transport, and ladder, exactly as it did before the kind existed.
  const passthrough: [string, unknown][] = [
    ["a raw string rejection", "ssh: connect failed: connection refused"],
    ["a bare Error", new Error("ssh: open channel failed: eof")],
    ["null", null],
    ["undefined", undefined],
    ["an empty object", {}],
    ["an unknown kind", { kind: "nonsense", message: "m" }],
    ["a kind with no message", { kind: "auth" }],
    ["a non-string message", { kind: "auth", message: 7 }],
  ];
  for (const [label, raw] of passthrough) {
    const out = sshConnectErrorFrom(raw);
    assert(out === raw, `${label} comes back identical (===)`);
    assert(
      decideSshConnectFailure(classifySshConnectFailure(out, "m")).action === "reconnect",
      `${label} still ladders - an unrecognised rejection never becomes a park`,
    );
  }
}

console.log("\n[end to end] rejected value -> wrapper -> classifier -> verdict");
{
  const verdictFor = (p: { kind: SshConnectErrorKind; message: string }) =>
    decideSshConnectFailure(classifySshConnectFailure(sshConnectErrorFrom(p), p.message)).action;
  for (const [p, expected] of [
    [PAYLOADS[0], "park"],
    [PAYLOADS[1], "park"],
    [PAYLOADS[2], "reconnect"],
  ] as [(typeof PAYLOADS)[number], string][]) {
    assert(
      verdictFor(p) === expected,
      `${p.kind} -> ${expected} (got ${verdictFor(p)}) - the whole path, not one hop of it`,
    );
  }
  // THE criterion the change exists for, stated once as its own row: a refused
  // credential costs one attempt, not four.
  assert(
    verdictFor(PAYLOADS[1]) !== verdictFor(PAYLOADS[2]),
    "a refused credential and a dropped link do NOT get the same answer",
  );
}

console.log("\n[regressions] the two things the raw object broke on its way through");
{
  // The "trust new key" prompt: `isHostKeyMismatchError` reads a prefix off
  // `.message`, and a plain object never had one. It is reported as `config`,
  // so it arrives here wrapped and the prefix is back.
  const mismatch = sshConnectErrorFrom({
    kind: "config",
    message: `${HOST_KEY_MISMATCH_PREFIX} expected=SHA256:aaa server=SHA256:bbb. The server presented a different key`,
  });
  assert(
    isHostKeyMismatchError(mismatch),
    "a host-key mismatch relayed through the new path still matches - the trust prompt survives",
  );
  assert(
    !isHostKeyMismatchError(sshConnectErrorFrom(PAYLOADS[1])),
    "and it does not match a refusal that merely arrived the same way",
  );

  // `describeError` is imported and CALLED here, not copied: it is the real
  // renderer both surfaces a user reads go through - the host editor's Test
  // button and a forward toast. It lives in `src/lib/describeError.ts`
  // precisely so a check can load it, which is why this section no longer
  // keeps a local twin that could pass while the shipped one disagreed.
  //
  // One assertion closes both symptoms. Unwrapped, `describeError` of the raw
  // payload is `{"kind":"config","message":…}` (the toast) and `String(...)` of
  // it is `[object Object]` (the Test button); wrapped, it is the sentence.
  for (const p of PAYLOADS) {
    assert(
      describeError(sshConnectErrorFrom(p)) === p.message,
      `${p.kind} renders as its sentence, not as JSON or [object Object]`,
    );
  }
  assert(
    describeError(PAYLOADS[0]) !== PAYLOADS[0].message,
    "and the assertion above is not vacuous - the UNWRAPPED payload renders as something else",
  );
}

// ============================================================================
// HOST KEYS: which of them the frontend may call its own fault.
//
// The rejected shape is the counter pair this replaced: `asked > trusted`,
// compared at failure time. It reads "a prompt was raised and never trusted"
// as "the user refused", and those are different worlds - a link that drops
// while the dialog is still on screen leaves a prompt raised and untrusted with
// nobody having refused anything, and parking it kills the ladder for exactly
// the blip the ladder exists for. The row that pins it is the empty one.

console.log("\n[hostKeyRefused] an ANSWER decides, and any refusal in a chain counts");
{
  // THE misfiling case, behaviourally: prompts were raised (that is why this is
  // even asked) and none were answered, because the transport died underneath
  // the dialog. Nothing was refused, so nothing is local, so the ladder stands.
  assert(
    !hostKeyRefused([]),
    "no answer at all -> NOT a refusal (the link dropped while the prompt was still on screen)",
  );
  assert(!hostKeyRefused([true]), "the one key was trusted -> not a refusal");
  assert(hostKeyRefused([false]), "the one key was refused -> a refusal");
  // The ProxyJump property the counters were protecting, kept: one question per
  // hop, and trusting the bastion says nothing about the target's key. Both
  // orders, because a latch that records the LAST answer passes one and fails
  // the other.
  assert(
    hostKeyRefused([true, false]),
    "bastion trusted, target refused -> still a refusal (a trust cannot mask it)",
  );
  assert(
    hostKeyRefused([false, true]),
    "target refused, then another hop trusted -> order does not change the verdict",
  );
  assert(!hostKeyRefused([true, true]), "every hop in the chain trusted -> not a refusal");
}

// ============================================================================
// RUST/TS PARITY: the pre-dial guard exists on both sides on purpose (the
// frontend needs it to CLASSIFY, the backend keeps it for its other callers -
// the forward tunnel and the host editor's Test probe). Two copies of a
// predicate is a drift risk, so the pairing is checked rather than trusted.

console.log("\n[parity] the backend guard and its frontend mirror agree");
{
  const rust = readRust("src-tauri/src/modules/ssh/session.rs");
  const ts = readTs("src/modules/terminal/lib/ssh-session.ts");

  const rustBody =
    /fn has_credential\([^)]*\)\s*->\s*bool\s*\{([\s\S]*?)\n\}/.exec(rust)?.[1] ?? "";
  assert(rustBody !== "", "found has_credential's body in session.rs");
  assert(
    /use_agent/.test(rustBody) && /password\.is_some\(\)/.test(rustBody),
    "the backend guard still tests PRESENCE (is_some), matching canAuthenticate above",
  );
  assert(
    !/is_empty\(\)|unwrap_or_default\(\)/.test(rustBody),
    "the backend guard has not been switched to an emptiness test the frontend does not mirror",
  );

  // Both call sites go through the one predicate. A third inline copy is how
  // the target and a jump hop start disagreeing about the same question.
  //
  // Counted INSIDE `connect` only. A whole-file count is not a check: the test
  // module below calls `has_credential` five more times, so deleting both real
  // call sites would still clear any file-wide threshold.
  const connectAt = rust.indexOf("pub async fn connect(");
  const connectOpen = rust.indexOf("{", connectAt);
  const connectBody =
    connectAt === -1 ? "" : rust.slice(connectOpen, matchingBrace(rust, connectOpen));
  assert(connectBody !== "", "found connect()'s body in session.rs");
  const callSites = connectBody.match(/has_credential\(/g) ?? [];
  assert(
    callSites.length === 2,
    `connect() asks the one predicate exactly twice - the target and each hop (found ${callSites.length})`,
  );
  assert(
    !/!\s*hop\.use_agent\s*&&/.test(rust),
    "the jump-hop guard no longer carries its own inline copy of the predicate",
  );

  const rustMsg = /const NO_CREDENTIALS_ERROR: &str = "([^"]*)"/.exec(rust)?.[1] ?? null;
  const tsMsg = /const NO_CREDENTIALS_MESSAGE = "([^"]*)"/.exec(ts)?.[1] ?? null;
  assert(rustMsg !== null, "found NO_CREDENTIALS_ERROR in session.rs");
  assert(tsMsg !== null, "found NO_CREDENTIALS_MESSAGE in ssh-session.ts");
  assert(
    rustMsg !== null && rustMsg === tsMsg,
    `the two sides tell the user the same sentence (rust=${JSON.stringify(rustMsg)}, ts=${JSON.stringify(tsMsg)})`,
  );
}

console.log("\n[parity] the connect-error kinds are the SAME SET on both sides");
{
  // Source-read, because a kind that exists in Rust and not here cannot be
  // exercised from a node script: it would arrive as an unrecognised payload,
  // pass through, and ladder - which is the safe fallback working exactly as
  // designed, and therefore invisible to every behavioural check above. This is
  // the only thing that notices.
  const rust = readRust("src-tauri/src/modules/ssh/session.rs");
  const ts = readTs("src/modules/ssh/bridge.ts");

  const rustEnum = /enum SshConnectErrorKind \{([^}]*)\}/.exec(rust)?.[1] ?? null;
  assert(rustEnum !== null, "found the SshConnectErrorKind enum in session.rs");
  // serde's `rename_all = "camelCase"` on single-word variants is just
  // lowercasing, which is what makes this comparison legitimate. The exact
  // serialized spelling is pinned in Rust by `connect_error_wire_tests`.
  const rustKinds = [...(rustEnum ?? "").matchAll(/\b([A-Z]\w*)\b/g)]
    .map((m) => m[1].toLowerCase())
    .sort();

  const tsUnion = /type SshConnectErrorKind =([^;]*);/.exec(ts)?.[1] ?? null;
  assert(tsUnion !== null, "found the SshConnectErrorKind union in bridge.ts");
  const tsKinds = [...(tsUnion ?? "").matchAll(/"(\w+)"/g)].map((m) => m[1]).sort();

  assert(rustKinds.length === 3, `Rust names three kinds (found ${rustKinds.join(",")})`);
  // The exact set, stringified - not "every Rust kind appears in TS". A
  // membership test passes when one side loses an arm, and losing `auth` is
  // precisely the regression that puts a refused credential back on the ladder.
  assert(
    JSON.stringify(rustKinds) === JSON.stringify(tsKinds),
    `the same set, both sides (rust=[${rustKinds}], ts=[${tsKinds}])`,
  );

  // The blanket `From` the error type must never gain. It would let `?` compile
  // at a site that named no kind, and whatever kind it picked would become the
  // silent default for every failure added after it - the compiler error at
  // each `?` is the entire enforcement mechanism.
  //
  // Counted, not pattern-matched on the `From` itself. `impl\s+From<[^>]*>\s+for`
  // cannot see `impl From<Box<dyn Error>> for SshConnectError`: the inner `>`
  // ends the character class early and leaves a `>` where the pattern wants
  // whitespace. Nesting is exactly what a real conversion impl would use, and
  // this one assert is the whole thing standing between the tree and the
  // documented failure mode, so it counts every impl instead.
  const impls = rust.match(/impl(?:<[^>]*>)?\s+[\w:<>, ]*\bfor\s+SshConnectError\b/g) ?? [];
  assert(
    impls.length === 1 && /\bDisplay\b/.test(impls[0]),
    `Display is the ONLY trait impl'd for SshConnectError - no From, no Error (found ${JSON.stringify(impls)})`,
  );
  // Constructors present, and the fields PRIVATE so they really are the only
  // way in. Without the private half a site could write the struct literal and
  // pick a kind without going through one, and a relay could rewrite `kind`
  // while re-wording `message` - which is how an absent ssh-agent reached the
  // ladder before.
  assert(
    /fn config\(/.test(rust) && /fn auth\(/.test(rust) && /fn transport\(/.test(rust),
    "all three constructors are still there",
  );
  const fields = /struct SshConnectError \{([^}]*)\}/.exec(rust)?.[1] ?? "";
  assert(fields !== "", "found the SshConnectError struct body");
  assert(
    !/\bpub\s+(?:kind|message)\s*:/.test(fields),
    `neither field is pub, so a struct literal cannot pick a kind (fields: ${JSON.stringify(fields.trim())})`,
  );
}

// ============================================================================
// THE FAILURE SITES THEMSELVES: which kind each one NAMES.
//
// Everything above this point takes a kind as given and proves what the app does
// with it. Nothing proves that the site which raises a failure picks the right
// one - and that is the only place the choice is actually made. The type system
// forces every site to NAME a kind (there is no blanket `From`, asserted above);
// it cannot force the name to be true. Change one `SshConnectError::auth(` in
// `connect` to `::transport(` and the headline defect is back in full - a wrong
// stored password walks 1s + 3s + 7s again - while every behavioural check in
// this file, the whole Rust suite, clippy and fmt stay green, because the TS
// payloads below are invented here and the Rust tests construct no failure at a
// site.
//
// Read as source, and scoped to ONE FUNCTION BODY at a time. A file-wide count
// proves nothing: the test module at the bottom of session.rs names these same
// functions and messages. Each row asserts the kind AND how many sites carry the
// message, because pinning one of a pair leaves the other free to drift.

console.log("\n[parity] each failure site still names the kind its category demands");
{
  const rust = readRust("src-tauri/src/modules/ssh/session.rs");

  /**
   * The whitespace-flattened body of the SOLE `decl` in session.rs, with the
   * hit count asserted. An anchor that resolves to nothing yields "", and every
   * `.test()` below "" is trivially false while every count is trivially zero -
   * a shape this file has been bitten by before, so the miss is reported here
   * rather than swallowed into a downstream row that reads as a pass.
   */
  const fnBody = (decl: string): string => {
    const hits = allIndexes(rust, decl);
    assert(
      hits.length === 1,
      `exactly one \`${decl}\` declaration in session.rs (found ${hits.length})`,
    );
    if (hits.length !== 1) return "";
    const open = rust.indexOf("{", hits[0]);
    const close = open === -1 ? -1 : matchingBrace(rust, open);
    assert(close > open, `resolved the body of \`${decl}\``);
    return close === -1
      ? ""
      : rust
          .slice(open + 1, close)
          .replace(/\s+/g, " ")
          .trim();
  };

  /**
   * The kind given to every construction of `message` in `body`, in source
   * order. The constructor must sit IMMEDIATELY before the literal (optionally
   * through a `format!(`), so a match cannot be borrowed from some unrelated
   * `SshConnectError::` earlier in the same function - which is how a
   * "nearest preceding constructor" search reads a neighbour's kind and calls
   * it a pass. A message that has moved or been reworded yields an EMPTY list,
   * and every caller asserts the length, so it fails loudly instead of
   * vacuously.
   */
  const kindsOf = (body: string, message: string): string[] =>
    allIndexes(body, message).map(
      (at) =>
        /SshConnectError::(\w+)\(\s*(?:format!\(\s*)?$/.exec(body.slice(0, at))?.[1] ??
        "<not constructed at this literal>",
    );

  const connect = fnBody("pub async fn connect(");
  assert(connect !== "", "extracted connect()'s body for the failure-site sweep");

  // THE headline row. Both of these are the SERVER'S ANSWER to a credential it
  // was given - the target's at the end of connect, and each jump hop's in the
  // chain loop - so both are `auth`, which parks. Either one filed as
  // `transport` puts a wrong saved password back on the 1s + 3s + 7s ladder for
  // that path, and no other check in this repo would notice. Counted as well as
  // kind-checked: pinning only the target leaves the jump-hop return free to
  // drift, and a ProxyJump user meets that one.
  const rejected = kindsOf(connect, '"ssh: authentication rejected');
  assert(
    rejected.length === 2 && rejected.every((k) => k === "auth"),
    `both "authentication rejected" returns in connect() are ::auth - the target's and the jump hop's (found ${JSON.stringify(rejected)})`,
  );

  // The pre-dial guards. Nothing was asked of any server, so a retry cannot
  // change the answer; `config` is what parks them. These are the failures the
  // whole ladder fix was opened for.
  assert(
    /SshConnectError::config\(NO_CREDENTIALS_ERROR\)/.test(connect),
    "the target's no-credentials guard returns ::config - a host saved with nothing to authenticate with must not dial four times",
  );
  const hopGuard = kindsOf(connect, '"ssh: jump host {} has no ssh-agent');
  assert(
    hopGuard.length === 1 && hopGuard[0] === "config",
    `the jump hop's no-credentials guard is ::config too (found ${JSON.stringify(hopGuard)})`,
  );

  // And the one site in connect that SHOULD ladder. Asserted so this section
  // cannot degenerate into "everything is a park": authentication has already
  // succeeded by here, so a channel that will not open is the link or a server
  // limit, and the next attempt may well get one.
  assert(
    /channel_open_session\(\)\s*\.await\s*\.map_err\(\|e\|\s*SshConnectError::transport\(/.test(
      connect,
    ),
    "channel_open_session's failure stays ::transport - post-auth, so it is the link, and it is what the ladder exists for",
  );
  const channel = kindsOf(connect, '"ssh: open channel failed');
  assert(
    channel.length === 1 && channel[0] === "transport",
    `one open-channel failure in connect(), still ::transport (found ${JSON.stringify(channel)})`,
  );

  const hop = fnBody("async fn authenticate_hop(");
  assert(hop !== "", "extracted authenticate_hop's body");

  // A key this MACHINE cannot decode - almost always a wrong passphrase. The
  // server was never asked, so it is not the server's answer; it is a fact
  // about this machine and retrying re-reads the same bytes. Pinned through the
  // `decode_secret_key` call itself as well as the message, so a rewording
  // cannot quietly detach the row from the site it is about.
  assert(
    /decode_secret_key\([^)]*\)\s*\.map_err\(\|e\|\s*\{\s*SshConnectError::config\(/.test(hop),
    "decode_secret_key's map_err builds ::config - a key that will not decode here is fixed until the user changes something",
  );
  const parse = kindsOf(hop, '"ssh: [{host}] parse private key failed');
  assert(
    parse.length === 1 && parse[0] === "config",
    `one parse-key failure in authenticate_hop, still ::config (found ${JSON.stringify(parse)})`,
  );

  // THE pair a future edit is most likely to "correct" to `auth`, because they
  // are lexically inside the authentication calls. They are not the server's
  // verdict: the verdict is the `.success()` these `?` operators run BEFORE, and
  // connect reads it. These are russh errors raised WHILE authenticating - the
  // socket died mid-exchange, the KEX broke - which is exactly the blip the
  // ladder is for. Filing them as `auth` parks a recoverable connection on the
  // first attempt and tells the user their password was refused when it was
  // never sent.
  for (const method of ["pubkey", "password"]) {
    const kinds = kindsOf(hop, `"ssh: [{host}] ${method} auth error`);
    assert(
      kinds.length === 1 && kinds[0] === "transport",
      `the ${method} map_err is ::transport, NOT ::auth - it is a russh error raised while authenticating, not the server's answer (found ${JSON.stringify(kinds)})`,
    );
  }
}

// ============================================================================
// THE WINDOWS ssh-agent ARM. Read rather than run, and read here rather than
// tested in Rust, because nothing else in the tree can reach it: `open_agent` is
// `#[cfg]`-split, needs a live transport, and CI runs this crate's tests on
// Linux only.
//
// What it protects: on Windows the Pageant fallback CONSTRUCTS SUCCESSFULLY with
// nothing listening, so "there is no agent on this machine" cannot be noticed
// where the transport opens. It surfaces one call later as a listing failure -
// indistinguishable from a live agent breaking mid-exchange, which is
// `transport`, which is the ladder. A machine with no agent at all therefore
// walked 1s + 3s + 7s while a RUNNING agent holding no key parked immediately,
// the exact inversion this change set out to remove. The marker `open_agent`
// hands back is the only thing that separates the two, and dropping it is a
// silent, platform-local regression.

console.log("\n[source-text] the Windows ssh-agent fallback marks itself UNPROVEN");
{
  const rust = readRust("src-tauri/src/modules/ssh/session.rs");

  /** The body of one `#[cfg(...)]`-gated `open_agent`, whitespace flattened. */
  const armBody = (cfg: string): string => {
    const head = new RegExp(`#\\[cfg\\(${cfg}\\)\\]\\s*async fn open_agent\\(\\)[^{]*\\{`).exec(
      rust,
    );
    if (!head) return "";
    const open = head.index + head[0].length - 1;
    const close = matchingBrace(rust, open);
    return close === -1
      ? ""
      : rust
          .slice(open + 1, close)
          .replace(/\s+/g, " ")
          .trim();
  };

  const windows = armBody("windows");
  const unix = armBody("not\\(windows\\)");
  assert(windows !== "", "found the #[cfg(windows)] open_agent body");
  assert(unix !== "", "found the #[cfg(not(windows))] open_agent body");

  // Both arms return the marker at all. Without it in the signature there is
  // nothing for `agent_keys` to read and the question is decided by the listing
  // error again.
  const signatures = rust.match(/async fn open_agent\(\)\s*->\s*[^{]+/g) ?? [];
  assert(
    signatures.length === 2 && signatures.every((s) => /Option<String>/.test(s)),
    `both open_agent arms return the proof marker (found ${JSON.stringify(signatures.map((s) => s.trim()))})`,
  );

  // The pipe arm completed a connect against something listening, so it is
  // proof: `None`. Asserted separately from the Pageant arm below - an arm that
  // marked EVERYTHING unproven would park a live agent that broke mid-exchange,
  // which is the opposite mistake and just as invisible from Linux.
  assert(
    /return Ok\(\(c\.dynamic\(\), None\)\);/.test(windows),
    "the named-pipe arm returns None - a completed connect IS proof of an agent",
  );

  // THE row. `connect_pageant` succeeding proves nothing, so its Ok arm must
  // carry `Some(...)`.
  assert(
    /Ok\(c\) => Ok\(\(c\.dynamic\(\), Some\(/.test(windows),
    "the Pageant fallback's success is marked UNPROVEN - Some(...), not None",
  );
  // And the sentence it carries is built where the pipe path is still in scope.
  // Rebuilding it later is impossible, and a marker with nothing in it would
  // leave the user a `config` park that never says which machine was looked at.
  assert(
    /let tried = format!\("no ssh-agent at \{pipe\} and no Pageant"\);/.test(windows),
    "the marker carries the sentence naming what was looked for, pipe path included",
  );
  // Both Pageant outcomes end at the same sentence: constructing-but-empty and
  // not-constructing-at-all are the same fact about this machine.
  assert(
    /Err\(SshConnectError::config\(format!\( "\{tried\} \(\{e\}\)\. \{NO_AGENT_HINT\}" \)\)\)/.test(
      windows,
    ),
    "a Pageant transport that will not open at all is config, on that same sentence",
  );

  // The Unix arm has no unproven case, and saying so is a check rather than a
  // comment: marking it `Some` would park every mid-exchange agent failure on
  // the platform where the socket connect really is evidence.
  assert(
    /\(c\.dynamic\(\), None\)/.test(unix) && !/Some\(/.test(unix),
    "the SSH_AUTH_SOCK arm is always proven - connect_env fails outright when nothing listens",
  );

  // And the marker is CONSULTED. `agent_keys` must hand it to the decision
  // function rather than reach for a constructor itself; a fresh
  // `SshConnectError::transport` at the listing site is the defect verbatim.
  const keysAt = rust.indexOf("pub(crate) async fn agent_keys(");
  const keysOpen = rust.indexOf("{", keysAt);
  const keys =
    keysAt === -1 ? "" : rust.slice(keysOpen, matchingBrace(rust, keysOpen)).replace(/\s+/g, " ");
  assert(keys !== "", "found agent_keys's body");
  assert(
    /\(mut agent, unproven\) = open_agent\(\)/.test(keys),
    "agent_keys binds the marker rather than discarding it",
  );
  const decided = keys.match(/agent_listing_error\(/g) ?? [];
  assert(
    decided.length === 1 && /agent_listing_error\(unproven\.as_deref\(\)/.test(keys),
    `the listing failure's kind comes from the marker, once (found ${decided.length} call(s))`,
  );
  // The timeout arm is the only constructor call left in there, and it is
  // deliberately transport - a wedged agent is what that bound exists for.
  const constructed = keys.match(/SshConnectError::(config|auth|transport)\(/g) ?? [];
  assert(
    constructed.length === 1 && constructed[0] === "SshConnectError::transport(",
    `the only kind agent_keys still picks itself is the AGENT_TIMEOUT one (found ${JSON.stringify(constructed)})`,
  );
}

// ============================================================================
// SOURCE TEXT: the decision has to be CONSULTED, and it has to CONTROL the
// ladder. Both retry sites are in files that cannot be imported under plain node
// (ssh-session.ts reaches `window` transitively - see the header of
// ssh-exit-decision.ts), and neither exposes its catch block as a pure function,
// so this half is read rather than run.
//
// Read by SCOPE, never by distance. This section used to compare
// character indices ("the gate's text comes before the ladder's in this block"),
// and two mutants walked through it green:
//
//   * the park arm loses its `return`, so a local failure parks AND THEN walks
//     1s + 3s + 7s. Every index assertion still held. That is the bug restored
//     in full, passing the check written to catch it.
//   * `const decision = …; void decision; scheduleSshReconnect(…)`. The verdict
//     is computed and dropped on the floor; `gate < ladder` cannot notice, and
//     its own label claimed the ladder was gated.
//
// What is asserted instead: resolve the innermost statement list the ladder call
// belongs to, and require a `parkSshConnectFailure` arm that is a sibling
// statement of it, earlier in that same list, and that TERMINATES the list. No
// index is compared to another index anywhere below.

/** Index of the delimiter matching the one at `openIdx`, or -1. */
function matchingDelim(src: string, openIdx: number, open: string, close: string): number {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    if (src[i] === open) depth++;
    else if (src[i] === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Index of the `}` matching the `{` at `openIdx`, or -1. */
function matchingBrace(src: string, openIdx: number): number {
  return matchingDelim(src, openIdx, "{", "}");
}

/** Every offset of `needle`, in source order - search by all matches, not the
 *  first: one `indexOf` examines whichever occurrence happens to come first,
 *  which is ordering luck rather than a check. */
function allIndexes(src: string, needle: string): number[] {
  const out: number[] = [];
  for (let at = src.indexOf(needle); at !== -1; at = src.indexOf(needle, at + 1)) out.push(at);
  return out;
}

/** The condition of the innermost `if` whose block contains `start`, or "". */
function guardAt(src: string, start: number): string {
  let at = start;
  if (at < 0) return "";
  // Bounded rather than `for (;;)`: eight levels is more nesting than anything
  // here has, and a bound cannot spin on a source this does not expect.
  for (let level = 0; level < 8; level++) {
    const { block, before } = scopeOf(src, at);
    const parts = before.split(";");
    const stmt = (parts[parts.length - 1] ?? "")
      .trim()
      .replace(/\b(?:void|await|return)$/, "")
      .trim();
    const own = /^if \((.*)\)$/s.exec(stmt);
    if (own) return own[1];
    // Some other statement head - a `for`, an arrow declaration, a call whose
    // argument list this needle sits inside. Not a guard, and not something to
    // look past either.
    if (stmt.length > 0 || block < 0) return "";
    at = block;
  }
  return "";
}

/**
 * The statement list around the SOLE occurrence of `anchor`.
 *
 * `hits` is reported rather than swallowed because the cheap trap is an
 * anchor that matches twice and an `indexOf` that takes whichever came first:
 * this section's previous anchor, `if (s.sshConnectionId) {`, occurs TWICE in
 * session-lifecycle.ts, and only source order put the spawn catch ahead of the
 * status re-emit at the bottom of `attachSession`. Reordering the file would
 * have silently pointed every assertion below at a block with no ladder in it -
 * and a block with no ladder in it passes a check for an ungated ladder.
 */
function soleBlockAround(
  src: string,
  anchor: string,
): { hits: number; open: number; close: number } {
  const hits = allIndexes(src, anchor);
  if (hits.length !== 1) return { hits: hits.length, open: -1, close: -1 };
  const open = scopeOf(src, hits[0]).block;
  return { hits: 1, open, close: open < 0 ? -1 : matchingBrace(src, open) };
}

/** Does this block body end by leaving the block, rather than falling out of the
 *  bottom of it? The single question the index comparison could not ask, and the
 *  one the "park loses its return" mutant turns on. */
function terminates(body: string): boolean {
  return /\b(?:return|throw)\b[^;{}]*;\s*$/.test(body);
}

/**
 * The park arm that lexically CONTROLS the ladder call at `ladderAt`: an `if`
 * whose block calls `parkSshConnectFailure`, whose block is a statement of the
 * very list the ladder call is a statement of, and which comes earlier in it.
 *
 * Sibling-of, not near: an arm nested one level deeper, or sitting in the
 * enclosing function rather than in this block, does not decide whether this
 * call runs, and neither does one that follows it.
 */
function parkArmControlling(
  src: string,
  list: number,
  ladderAt: number,
): { guard: string; body: string } | null {
  for (const p of allIndexes(src, "parkSshConnectFailure(")) {
    if (p > ladderAt) continue;
    const armOpen = scopeOf(src, p).block;
    // -1 is the function DECLARATION of parkSshConnectFailure at module scope,
    // which is not an arm of anything.
    if (armOpen < 0) continue;
    if (scopeOf(src, armOpen).block !== list) continue;
    const armClose = matchingBrace(src, armOpen);
    if (armClose === -1) continue;
    return { guard: guardAt(src, p), body: src.slice(armOpen + 1, armClose) };
  }
  return null;
}

/**
 * Both catch sites, asserted identically. The first attempt (session-lifecycle)
 * and the ladder's own re-entry (ssh-session) have to answer the same question,
 * so they are checked by one body of code rather than by two that could drift.
 *
 * Anchored on `isHostKeyMismatchError(e)`: the one statement that is unambiguous
 * in BOTH files (the import spells the name without `(e)`), and one that belongs
 * to this decision rather than to the logging around it - it is the other
 * unretryable category, and it can only ever live in the connect-failure catch.
 * Its uniqueness is asserted rather than assumed.
 */
function checkLadderSite(label: string, rel: string): void {
  const src = readTs(rel);
  const region = soleBlockAround(src, "isHostKeyMismatchError(e)");
  assert(region.hits === 1, `${label}: the anchor occurs exactly once (found ${region.hits})`);
  assert(
    region.open >= 0 && region.close > region.open,
    `${label}: resolved the connect-failure catch block around the anchor`,
  );
  if (region.open < 0 || region.close < 0) return;

  const regionText = src.slice(region.open, region.close);
  const verdict =
    /(?:const|let)\s+(\w+)\s*=\s*decideSshConnectFailure\(\s*classifySshConnectFailure\(\s*e\s*,/.exec(
      regionText,
    );
  assert(
    verdict !== null,
    `${label}: the catch classifies the error IT caught and keeps the verdict`,
  );

  const sites = allIndexes(src, "scheduleSshReconnect(").filter(
    (at) => at > region.open && at < region.close,
  );
  assert(
    sites.length === 1,
    `${label}: exactly one scheduleSshReconnect call in that catch (found ${sites.length})`,
  );
  for (const at of sites) {
    const list = scopeOf(src, at).block;
    assert(list >= 0, `${label}: resolved the block that lexically controls the ladder call`);
    const arm = list < 0 ? null : parkArmControlling(src, list, at);
    assert(
      arm !== null,
      `${label}: a parkSshConnectFailure arm is a sibling statement of the ladder call, earlier in the same block`,
    );
    assert(
      arm !== null && terminates(arm.body),
      `${label}: the park arm TERMINATES that block - falling out of it parks AND ladders`,
    );
    assert(
      arm !== null &&
        verdict !== null &&
        new RegExp(`\\b${verdict[1]}\\.action\\b`).test(arm.guard) &&
        /"park"/.test(arm.guard),
      `${label}: the arm is taken on the classifier's own verdict (guard: ${JSON.stringify(arm?.guard ?? "")})`,
    );
  }
}

console.log("\n[source-text] the dial's rejection cannot get past the boundary unwrapped");
{
  // Every behavioural check above calls `sshConnectErrorFrom` itself, so all of
  // them stay green if `openSsh` stops calling it and lets the raw `{kind,
  // message}` through - which is the whole defect, restored in full. `openSsh`
  // invokes a Tauri command and cannot be run from here, so this one property
  // is read rather than called. It is the only check that notices.
  const src = readTs("src/modules/ssh/bridge.ts");

  const dials = allIndexes(src, 'invoke<number>("ssh_open"');
  assert(dials.length === 1, `one ssh_open dial in bridge.ts (found ${dials.length})`);
  const argOpen = dials.length === 1 ? src.indexOf("(", dials[0]) : -1;
  const argClose = argOpen === -1 ? -1 : matchingDelim(src, argOpen, "(", ")");
  assert(argClose > argOpen, "resolved the dial's argument list");

  // Attached to THIS call, not merely present in the function. A `.catch` on
  // some other promise in the same body would satisfy a whole-file grep and
  // leave the dial's own rejection untouched.
  const tail = argClose === -1 ? "" : src.slice(argClose + 1);
  const guardOpen = /^\s*\.catch\s*\(/.exec(tail);
  assert(guardOpen !== null, "the dial's own promise carries a .catch, chained to it directly");
  const handlerAt = guardOpen === null ? -1 : argClose + guardOpen[0].length;
  const handlerEnd = handlerAt === -1 ? -1 : matchingDelim(src, handlerAt - 1, "(", ")");
  const handler = handlerEnd === -1 ? "" : src.slice(handlerAt, handlerEnd);
  // THROWS it. Computing the wrapper and returning it would resolve the dial
  // with an Error instead of rejecting, so `openSsh` would hand back a bogus
  // session id and the catch sites downstream would never run at all.
  assert(
    /\bthrow\s+sshConnectErrorFrom\(/.test(handler),
    `the handler THROWS the wrapped error (handler: ${JSON.stringify(handler.trim())})`,
  );

  // And that call is the only one: a second reader of the payload elsewhere in
  // this file would be a second place to keep in step with the Rust kinds.
  const calls = allIndexes(src, "sshConnectErrorFrom(").length;
  assert(
    calls === 2,
    `sshConnectErrorFrom appears exactly twice - its declaration and this one call (found ${calls})`,
  );
}

console.log("\n[source-text] the first attempt's catch: the park arm controls the ladder");
checkLadderSite("first attempt", "src/modules/terminal/lib/session-lifecycle.ts");

console.log("\n[source-text] the ladder's own re-entry: same question, same answer");
checkLadderSite("attempts 2 and 3", "src/modules/terminal/lib/ssh-session.ts");

console.log("\n[source-text] nothing is dialled that could not authenticate");
{
  const src = readTs("src/modules/terminal/lib/ssh-session.ts");
  // Everything from the resolve block down to the dial itself: the property is
  // "asked BEFORE openSsh", so the region is bounded by the call rather than by
  // a brace, and a check that drifted below the dial would fall out of it.
  // Both bounds are asserted unambiguous - a second `await openSsh(` would make
  // "before the dial" mean "before whichever one came first".
  const fromHits = allIndexes(src, "let jumps: SshJumpHop[];");
  const dialHits = allIndexes(src, "sshSession = await openSsh(");
  assert(fromHits.length === 1, `one resolve block opens the region (found ${fromHits.length})`);
  assert(dialHits.length === 1, `one dial closes it (found ${dialHits.length})`);
  const from = fromHits.length === 1 ? fromHits[0] : -1;
  const dial = dialHits.length === 1 ? dialHits[0] : -1;
  const body = from !== -1 && dial > from ? src.slice(from, dial) : null;
  assert(body !== null, "found the region between the resolve block and the dial");
  assert(
    /canAuthenticate\(auth\)/.test(body ?? ""),
    "the target's credential is checked before openSsh is called",
  );
  assert(
    /canAuthenticate\(hop\)/.test(body ?? ""),
    "every ProxyJump hop's credential is checked too - a chain fails the same way",
  );
  // The resolve block's catch re-wraps whatever it threw, which is what makes a
  // failure ADDED to that block later local by default. Losing this line is how
  // the next pre-flight error silently rejoins the ladder.
  assert(
    /new SshLocalConnectError\(message/.test(body ?? ""),
    "the resolve block's catch re-wraps every failure as local, not just the ones it raises itself",
  );
}

console.log("\n[source-text] a REFUSED host key is a local decision - an unanswered one is not");
{
  const src = readTs("src/modules/terminal/lib/ssh-session.ts");

  // A list of answers, not a latch on "was one trusted". The type is asserted
  // because it is the multi-hop property in one token: a `boolean` cannot hold
  // "the bastion said yes and the target said no", and a chain is exactly where
  // the counters this replaces were pointed.
  const record = /const (\w+): boolean\[\] = \[\];/.exec(src);
  assert(record !== null, "the attempt keeps a LIST of host-key answers, not a single verdict");
  // A name no identifier can have, so the assertions below fail loudly rather
  // than searching for "" and matching at every offset in the file.
  const answers = record?.[1] ?? "<no record>";

  // The queue routes every answer through the prompt's own `confirm` - the
  // user's Trust, the user's Reject, and the rejection `abandon` sends when
  // whatever asked the question has gone away. Wrapping it is what lets the
  // answer be recorded AS IT IS MADE instead of guessed at afterwards.
  const enqueueHits = allIndexes(src, ".enqueue(");
  const confirmHits = allIndexes(src, "confirm: (");
  assert(enqueueHits.length === 1, `the connect enqueues one prompt (found ${enqueueHits.length})`);
  assert(confirmHits.length === 1, `carrying one confirm wrapper (found ${confirmHits.length})`);
  const argOpen = enqueueHits.length === 1 ? src.indexOf("{", enqueueHits[0]) : -1;
  const argClose = argOpen === -1 ? -1 : matchingBrace(src, argOpen);
  const confirmAt = confirmHits.length === 1 ? confirmHits[0] : -1;
  assert(
    confirmAt > argOpen && argOpen !== -1 && confirmAt < argClose,
    "the wrapper is a field of the prompt handed to enqueue - anywhere else and the queue calls the bare command instead",
  );
  const confirmBody = confirmAt === -1 ? -1 : src.indexOf("{", src.indexOf("=>", confirmAt));
  assert(confirmBody > 0, "found the wrapper's body");
  assert(
    /confirmHostKey\(/.test(
      confirmBody === -1 ? "" : src.slice(confirmBody, matchingBrace(src, confirmBody)),
    ),
    "the wrapper still forwards the answer - the paused handshake is blocked on this very call",
  );

  // THE misfiling regression, in source terms: recording an answer where the
  // PROMPT is raised rather than where it is answered restores `asked > trusted`
  // under a new name, and files a link that dropped under the dialog as a local
  // refusal. Every write to the record must sit in the wrapper.
  const writes = allIndexes(src, `${answers}.push(`);
  assert(
    writes.length === 1,
    `the record is written from exactly one place (found ${writes.length})`,
  );
  assert(
    writes.length > 0 && writes.every((at) => scopeOf(src, at).block === confirmBody),
    "the record is written only from the answer wrapper, never where a prompt is merely raised",
  );

  // Pinning stays on the accept callback. In the wrapper it would fire for every
  // answer, which means pinning a key the user just REFUSED.
  const pins = allIndexes(src, "pinFingerprint(");
  assert(pins.length === 1, `the fingerprint is pinned from one place (found ${pins.length})`);
  assert(
    pins.length === 1 && scopeOf(src, pins[0]).block !== confirmBody,
    "pinning is on the accept path, not on every answer",
  );

  // And the catch reads the verdict, rather than any restatement of "a prompt
  // was raised and not trusted".
  const marker = allIndexes(src, "throw new SshLocalConnectError(describeError(e)");
  assert(
    marker.length === 1,
    `one host-key local marker in the connect catch (found ${marker.length})`,
  );
  const guard = marker.length === 1 ? guardAt(src, marker[0]) : "";
  assert(
    guard === `hostKeyRefused(${answers})`,
    `the marker is thrown only for a REFUSAL, nothing weaker (guard: ${JSON.stringify(guard)})`,
  );
}

console.log(failed === 0 ? "\nAll ssh-retry checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
