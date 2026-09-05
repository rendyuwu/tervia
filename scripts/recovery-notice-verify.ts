/**
 * Self-check: a `.bak` recovery is SAID OUT LOUD.
 * Run: `npx tsx scripts/recovery-notice-verify.ts`.
 *
 * `createRecoveredStore` has produced a recovery notice since it was written,
 * and `ensureLoaded()` / `takeRecoveryNotice()` had no caller anywhere in `src/`
 * - only in verify scripts. A tester recovered from corruption twice and was
 * told nothing either time.
 *
 * What is checked here is the policy: that the startup pass is asked exactly
 * once per store, that a notice becomes a toast naming the store and the backup,
 * that a store with nothing to report stays silent, and that the whole thing is
 * total - a rejecting store must not take the launch with it, because the caller
 * is fire-and-forget.
 *
 * NOT checked here: that `App.tsx` mounts the hook, and that the hook asks each
 * store once per LAUNCH (a `useRef` guard). Both need React. The mount is
 * asserted by source text at the end, which is exactly as strong as reading it.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import type { StoreRecovery } from "../src/lib/storeRecovery";
import {
  announceRecovery,
  drainRecovery,
  recoveryToast,
  type RecoverableStore,
  type RecoveryToast,
} from "../src/app/lib/recoveryNotices";

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

/** A store whose pass returns whatever the test wants, counting the asks. */
function fakeStore(notice: StoreRecovery | null, label = "Saved machines") {
  const calls = { ensureLoaded: 0, take: 0 };
  let held = notice;
  const store: RecoverableStore = {
    label,
    ensureLoaded: async () => {
      calls.ensureLoaded++;
      const out = held;
      // The real port hands the notice out ONCE. Modelling that is what makes
      // the "asked exactly once" check below mean something.
      held = null;
      return out;
    },
    takeRecoveryNotice: () => {
      calls.take++;
      const out = held;
      held = null;
      return out;
    },
    onChanged: async () => () => {},
  };
  return { store, calls };
}

function recorder() {
  const said: RecoveryToast[] = [];
  return { said, say: (t: RecoveryToast) => void said.push(t) };
}

const RECOVERED: StoreRecovery = {
  found: "unparseable",
  recovered: true,
  note: "tervia-hosts.json was unparseable; restored from tervia-hosts.json.bak",
};
const SNAPSHOT_FAILED: StoreRecovery = {
  found: "ok",
  recovered: false,
  note: "tervia-vault.json.bak could not be written: EACCES",
};
const NOTHING_TO_SAY: StoreRecovery = { found: "ok", recovered: false };

// ---- the words ------------------------------------------------------------
console.log("[copy] a recovery names the store and says where the data came from");
{
  const t = recoveryToast("Saved machines", RECOVERED);
  check("there is something to say", t !== null);
  check("it names the store", !!t && t.message.startsWith("Saved machines:"), t?.message);
  check("it says the data came from a backup", !!t && /recovered from a backup/i.test(t.message));
  check(
    // The note is where the file names live; paraphrasing it here would be a
    // second copy of wording that belongs to `lib/storeRecovery.ts`.
    "the notice's own detail is passed through verbatim",
    !!t && t.message.includes(RECOVERED.note!),
    t?.message,
  );
  check("as a warning, not an error", t?.variant === "warning", t?.variant);
  check(
    // Nothing in this app may suggest that storing a secret here makes it safer,
    // and a restored store is not a safer store - the snapshot is metadata from
    // the last process start while the keychain is current.
    "and it claims nothing about safety, protection or encryption",
    !!t && !/safe|secure|protect|encrypt/i.test(t.message),
    t?.message,
  );
  check(
    // The other half of the same honesty, and the one that costs a user
    // something when it is missing: the file went back, the OS keychain did not,
    // so a restored record's `hasPrivateKey` / `hasPassword` / `fingerprint` can
    // name a secret that has since been deleted or rotated. Nothing in the app
    // reconciles the two and nothing can enumerate the keychain to find out, so
    // saying it is the whole of what is done about it.
    "and it says the stored secrets did not come back with the file",
    !!t && /not rolled back with it/.test(t.message),
    t?.message,
  );
  check(
    "without claiming the app did anything about that",
    !!t && !/fixed|repaired|reconciled|restored your|re-?check/i.test(t.message),
    t?.message,
  );
}
{
  const t = recoveryToast("Vault", SNAPSHOT_FAILED);
  check("a note with no recovery is still said", t !== null);
  check("named the same way", !!t && t.message.startsWith("Vault:"), t?.message);
  check("as an error - it is something the app could NOT do", t?.variant === "error", t?.variant);
  check(
    "and it does not claim a recovery that did not happen",
    !!t && !/recovered from a backup/i.test(t.message),
    t?.message,
  );
  check(
    // Nothing was rolled back on this branch, so the keychain cannot have
    // diverged from anything. Warning here would be a warning about a hazard
    // that is not present, on the toast a user sees when a `.bak` merely could
    // not be written.
    "nor does it warn about a rollback that did not happen",
    !!t && !/not rolled back with it/.test(t.message),
    t?.message,
  );
}
check("a notice with no note says nothing at all", recoveryToast("Vault", NOTHING_TO_SAY) === null);

// ---- the startup pass ---------------------------------------------------
console.log("\n[startup] each store is asked once, and a recovery reaches the user");
{
  const { store, calls } = fakeStore(RECOVERED);
  const { said, say } = recorder();
  await announceRecovery(store, say);
  check("the recovery pass ran", calls.ensureLoaded === 1, calls);
  // Distinct from the check above, not a restatement of it: `announceRecovery`
  // goes through `ensureLoaded` alone. A version that ALSO called
  // `takeRecoveryNotice` (the drain-only method `drainRecovery` uses instead)
  // would double-drain the slot on a startup pass and this would catch it.
  check("and never separately drains via takeRecoveryNotice", calls.take === 0, calls);
  check("one toast, not none", said.length === 1, said);
  check("naming the store", said[0]?.message.startsWith("Saved machines:"), said[0]?.message);
}
{
  // The ordinary launch: nothing was wrong, so nothing is said. Without this
  // check a hook that toasted unconditionally would pass everything above.
  const { store, calls } = fakeStore(null);
  const { said, say } = recorder();
  await announceRecovery(store, say);
  check("a clean store is still asked", calls.ensureLoaded === 1, calls);
  check("and says nothing", said.length === 0, said);
}
{
  const { store } = fakeStore(NOTHING_TO_SAY);
  const { said, say } = recorder();
  await announceRecovery(store, say);
  check("a notice with no note says nothing either", said.length === 0, said);
}
{
  // Fire-and-forget: a throwing pass must not become an unhandled rejection.
  const store: RecoverableStore = {
    label: "Vault",
    ensureLoaded: () => Promise.reject(new Error("boom")),
    takeRecoveryNotice: () => null,
    onChanged: async () => () => {},
  };
  const { said, say } = recorder();
  let threw = false;
  // `announceRecovery` logs the swallowed error, which is the right thing for it
  // to do and an alarming stack trace in the middle of passing output. Muted for
  // this one call so a reader can tell a real failure from a provoked one.
  const realError = console.error;
  console.error = () => {};
  await announceRecovery(store, say).catch(() => {
    threw = true;
  });
  console.error = realError;
  check("a rejecting store is swallowed, not propagated", !threw);
  check("and says nothing", said.length === 0, said);
}

// ---- the post-startup drain --------------------------------------------
console.log("\n[later] a note that lands after startup is not lost");
{
  // A `.bak` that could not be written after a save fills the slot mid-session.
  const { store, calls } = fakeStore(SNAPSHOT_FAILED, "Vault");
  const { said, say } = recorder();
  drainRecovery(store, say);
  check("the slot is drained", calls.take === 1, calls);
  check("and the note is said", said.length === 1, said);
  drainRecovery(store, say);
  check("draining again says nothing - the notice is handed out once", said.length === 1, said);
}

// ---- the real once-per-launch guarantee (behavioural) ---------------------
// The hook's comment used to credit `startedRef` for the once-per-launch
// guarantee. A `useRef` does not survive a genuine unmount/remount of App - a
// fresh mount gets a fresh ref and would ask again - so that was never the
// real mechanism (see the corrected comment in useStoreRecoveryNotices.ts).
// What actually stops a second toast is `createRecoveredStore`'s notice slot
// being DRAINED by the first `ensureLoaded()` call. Proven directly here, at
// the layer it actually happens - `lib/recoveredStore.ts`, with injected
// ports so it runs under plain node - with no React and no `startedRef`
// anywhere in the picture.
console.log("\n[drain] the real once-per-launch guarantee: ensureLoaded() drains the slot");
{
  const { createRecoveredStore } = await import("../src/lib/recoveredStore");
  // A torn primary with a good `.bak` beside it, so the recovery pass has a
  // real notice to hand out - same shape as the [copy]/[startup] fixtures
  // above, but exercised through the real store rather than a fake `Say`.
  let primary = "not json";
  const files = {
    dir: async () => "/fake",
    read: async (path: string) =>
      path.endsWith(".bak")
        ? ({ kind: "text", content: '{"ok":true}' } as const)
        : ({ kind: "text", content: primary } as const),
    write: async (path: string, content: string) => {
      if (!path.endsWith(".bak")) primary = content;
    },
  };
  const kv = { get: async () => undefined, set: async () => {}, save: async () => {} };
  const broadcast = { emit: async () => {}, listen: async () => () => {} };
  const io = createRecoveredStore(
    { path: "fake.json", loadKey: "k", changedEvent: "fake-changed" },
    { store: kv, files, broadcast },
  );
  const first = await io.ensureLoaded();
  check(
    "first ensureLoaded() reports the recovery",
    first !== null && first.recovered === true,
    first,
  );
  const second = await io.ensureLoaded();
  check(
    // The whole guarantee, in one call: a SECOND ask - modelling a
    // StrictMode double-invoke of the hook's effect, or a genuine remount
    // asking again with no memory of the first - finds the slot already
    // drained. No ref, no React, nothing per-component involved.
    "a second ensureLoaded() finds the slot already drained",
    second === null,
    second,
  );
}

// ---- the wiring (source text only) -------------------------------------
// Honest about its strength: these read the files, they do not run them. They
// exist because the whole defect was a caller that did not exist, and nothing
// runnable here can tell a mounted hook from an unmounted one.
console.log("\n[wiring] source text: the hook exists, is mounted, and uses the real stores");
{
  const app = read("src/app/App.tsx");
  const hook = read("src/app/hooks/useStoreRecoveryNotices.ts");
  check("App imports the hook", app.includes('from "./hooks/useStoreRecoveryNotices"'));
  check("App calls it", /useStoreRecoveryNotices\(\);/.test(app));
  check(
    "the hook asks the hosts store",
    hook.includes('from "@/modules/hosts/store"') && hook.includes("ensureHostsLoaded"),
  );
  check(
    "the hook asks the vault store",
    hook.includes('from "@/modules/vault/store"') && hook.includes("ensureVaultLoaded"),
  );
  check(
    "the hook asks the forwards store",
    hook.includes('from "@/modules/forwards/store"') && hook.includes("ensureForwardsLoaded"),
  );
  check(
    // NOT the once-per-launch guarantee itself - the [drain] check above is
    // what pins that, at the layer it actually holds. This only pins that
    // the hook still has its own same-mount guard (StrictMode double-invoke
    // of THIS effect), which is a real but much narrower property.
    "the hook guards its own effect body with startedRef",
    hook.includes("startedRef.current"),
  );
  check("and it toasts what comes back", hook.includes("toast(t.message"));
}

// ---- the list stays complete (structural) -------------------------------
// The defect this whole script exists for was a list with a store missing from
// it, and the two source-text checks above cannot catch the next one: they name
// the three stores that ARE listed, so a fourth store added tomorrow passes them
// all while saying nothing when it recovers.
//
// So: set EQUALITY between the modules that PRODUCE a recovery notice (every
// `src/modules/*/store.ts` re-exporting `takeRecoveryNotice`, which is generic -
// `createRecoveredStore` gives one to whatever is built on it) and the modules
// the hook CONSUMES. Membership would catch a store removed from the list and
// not one that was never added, and never-added is the failure that happened.
//
// Compiler API rather than `indexOf`, per this repository's rule for structural
// checks: an absent anchor is a state a text search does not have, and both
// sides here are shapes (an export list, an array of object literals) rather
// than strings. Order is deliberately NOT the property - both sides are sorted,
// so rearranging `STORES` stays green.
console.log("\n[complete] every store that produces a recovery notice is in the list");
{
  const parse = (rel: string): ts.SourceFile =>
    ts.createSourceFile(rel, read(rel), ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS);

  /** Every name a source file exports, in whichever form it exports it. */
  function exportedNames(sf: ts.SourceFile): Set<string> {
    const out = new Set<string>();
    const exported = (n: ts.Node): boolean =>
      ts.canHaveModifiers(n) &&
      !!ts.getModifiers(n)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    for (const st of sf.statements) {
      if (ts.isVariableStatement(st) && exported(st)) {
        for (const d of st.declarationList.declarations) {
          // `export const takeRecoveryNotice = ...` and the destructured
          // `export const { ..., takeRecoveryNotice } = forwardsStore` that the
          // three stores actually use.
          if (ts.isIdentifier(d.name)) out.add(d.name.text);
          else if (ts.isObjectBindingPattern(d.name)) {
            for (const el of d.name.elements) {
              if (ts.isIdentifier(el.name)) out.add(el.name.text);
            }
          }
        }
      } else if (
        (ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st)) &&
        exported(st) &&
        st.name
      ) {
        out.add(st.name.text);
      } else if (
        ts.isExportDeclaration(st) &&
        st.exportClause &&
        ts.isNamedExports(st.exportClause)
      ) {
        for (const el of st.exportClause.elements) out.add(el.name.text);
      }
    }
    return out;
  }

  // Every `.ts` under `src/modules`, not just `<module>/store.ts`: the CLI-agent
  // store lives at `modules/terminal/lib/cliAgents.ts`, and a producer set that
  // only looked at store files would have missed it - which is this check's own
  // failure mode, one level up.
  function tsFilesUnder(dir: string): string[] {
    const out: string[] = [];
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) out.push(...tsFilesUnder(full));
      else if (name.endsWith(".ts")) out.push(full);
    }
    return out;
  }

  const modulesDir = join(repoRoot, "src", "modules");
  const producers = tsFilesUnder(modulesDir)
    .map((full) =>
      full
        .slice(repoRoot.length + 1)
        .split("\\")
        .join("/"),
    )
    .filter((rel) => exportedNames(parse(rel)).has("takeRecoveryNotice"))
    // Back to the `@/modules/...` specifier the hook would import it by, so both
    // sides of the comparison are the same kind of name.
    .map((rel) => rel.replace(/^src\//, "@/").replace(/\.ts$/, ""))
    .sort();

  const hookRel = "src/app/hooks/useStoreRecoveryNotices.ts";
  const hookSf = parse(hookRel);

  // Local name -> module specifier, for every `takeRecoveryNotice` the hook
  // imports. Going through the import list rather than matching on the alias's
  // spelling means a rename is followed rather than silently dropped.
  const aliasToModule = new Map<string, string>();
  for (const st of hookSf.statements) {
    if (!ts.isImportDeclaration(st) || !ts.isStringLiteral(st.moduleSpecifier)) continue;
    const spec = st.moduleSpecifier.text;
    const bindings = st.importClause?.namedBindings;
    if (!spec.startsWith("@/modules/") || !bindings || !ts.isNamedImports(bindings)) continue;
    for (const el of bindings.elements) {
      if ((el.propertyName ?? el.name).text === "takeRecoveryNotice") {
        aliasToModule.set(el.name.text, spec);
      }
    }
  }

  let entries = 0;
  const consumers: string[] = [];
  const visit = (n: ts.Node): void => {
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === "STORES" &&
      n.initializer &&
      ts.isArrayLiteralExpression(n.initializer)
    ) {
      for (const el of n.initializer.elements) {
        if (!ts.isObjectLiteralExpression(el)) continue;
        entries++;
        for (const p of el.properties) {
          if (!ts.isPropertyAssignment(p)) continue;
          if (p.name.getText(hookSf) !== "takeRecoveryNotice") continue;
          const mod = aliasToModule.get(p.initializer.getText(hookSf));
          if (mod) consumers.push(mod);
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(hookSf);

  check(`the hook's STORES array was found and read (${entries} entries)`, entries > 0, entries);
  check(
    // Otherwise an entry whose `takeRecoveryNotice` came from somewhere this
    // does not follow would drop out of the consumer set unnoticed, and the
    // equality below could hold for the wrong reason.
    "every entry's takeRecoveryNotice resolves to a module store",
    consumers.length === entries,
    { entries, resolved: consumers },
  );
  check(
    "the stores that produce a notice are exactly the stores the hook lists",
    JSON.stringify(producers) === JSON.stringify([...consumers].sort()),
    { producers, consumers: [...consumers].sort() },
  );
}

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
