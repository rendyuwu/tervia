/**
 * Self-check for wave 2 step 3: the Vault page SHELL - the rail-view branch
 * swap in `RailViewArea.tsx`, and `VaultPage.tsx` itself, which is assembly
 * only. Run: `pnpm verify vault-shell` (or `npx tsx
 * scripts/vault-shell-verify.ts` to iterate).
 *
 * SOURCE-TEXT, exactly as `hosts-page-verify.ts` and `hosts-error-toast-verify.ts`
 * are - there is no DOM or layout engine in this suite - with ONE exception:
 * sections 3 and 6 use the TypeScript compiler API (`scripts/pane-caret-verify.ts`
 * is the precedent), because both are nesting questions, and a distance
 * heuristic reads a correctly-nested call as un-nested. "Is this call inside a
 * `useMemo(...)`" and "is this call inside `confirmDelete`'s body" are both
 * shapes a regex cannot tell from "these two strings happen to be near each
 * other" - and getting either wrong is a false PASS on exactly the defect the
 * section exists to catch (see the header note on M3 below).
 *
 * Every section states, in a comment, the ONE property it protects - most of
 * them are re-derivation smells or missing-nesting bugs that this page's own
 * wave-1/wave-2 siblings already shipped once (see `derive.ts`'s own header for
 * why the row builders live where they do).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

let failed = 0;
function check(name: string, ok: boolean, detail?: string | number): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

const FILES = {
  vaultPage: "src/modules/vault/VaultPage.tsx",
  identityCard: "src/modules/vault/page/IdentityCard.tsx",
  keyCard: "src/modules/vault/page/KeyCard.tsx",
  railViewArea: "src/app/components/RailViewArea.tsx",
} as const;

const src = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, read(p)])) as Record<
  keyof typeof FILES,
  string
>;

// The three files this wave's other checks call "the three new files" -
// VaultPage.tsx plus the two cards next to it. `RailViewArea.tsx` is an
// EDIT, not a new file, and is deliberately excluded from every whole-suite
// sweep below (sections 9 and 12) for that reason.
const NEW_FILES = ["vaultPage", "identityCard", "keyCard"] as const;

// ============================================================================
// 1. The rail branch was replaced, and only that branch.
// ============================================================================
// Protects: `RailViewArea.tsx`'s `vault` case renders `<VaultPage />`, its
// `PagePlaceholder` call is gone, and - the negative control - the `forwards`
// case (6f's, untouched) still renders its placeholder. The third check is
// what stops an edit that replaced BOTH branches from reading as correct: M2
// below flips `forwards` to `<VaultPage />` too, and only the third check can
// notice.
console.log("[1. rail branch] only the vault case was replaced");
{
  const r = src.railViewArea;
  check(
    "the vault case renders <VaultPage />",
    /case "vault":[\s\S]{0,200}<VaultPage\s*\/>/.test(r),
  );
  check(
    "the vault case no longer renders PagePlaceholder",
    !/case "vault":[\s\S]{0,200}PagePlaceholder/.test(r),
  );
  check(
    'NEGATIVE CONTROL: the forwards case still renders <PagePlaceholder page="forwards"',
    /case "forwards":[\s\S]{0,200}<PagePlaceholder page="forwards"/.test(r),
  );
}

// ============================================================================
// 2. The page calls the shared row builders and assembles nothing itself.
// ============================================================================
// Protects: the Hosts page and the header quick-connect once disagreed about
// which hosts a query matched because each assembled its own rows instead of
// calling one shared builder (`page/derive.ts`'s own header tells that story).
// The negative half runs over the RAW source - comments and dead branches
// included - because "this page never re-derives X" has to hold everywhere in
// the file, not just in the reachable lines.
console.log("\n[2. no re-derivation] the page calls the shared builders, not its own logic");
{
  const v = src.vaultPage;
  for (const name of ["identityRows(", "keyRows(", "rankIdentities(", "rankKeys("]) {
    check(`VaultPage.tsx calls ${name}`, v.includes(name));
  }
  for (const smell of ["credential.identityId", "credential.kind", ".keyId ===", "hasPrivateKey"]) {
    check(`VaultPage.tsx does not re-derive via \`${smell}\``, !v.includes(smell));
  }
}

// ============================================================================
// 3. Every row-builder call is inside a useMemo. (COMPILER API)
// ============================================================================
// Protects: zustand v5 matches `Object.is`, and each row builder ends in
// `.map` - a fresh array every call. A call site that is not wrapped re-renders
// on every store broadcast and, called from a selector, throws "Maximum
// update depth exceeded" outright; called from the render body, it just
// re-derives every render for nothing. THIS IS THE CHECK M3 IS FOR: a check
// that only greps for `useMemo(` anywhere in the file passes over "hoist the
// call out of its useMemo into the render body", because the text `useMemo(`
// is still sitting a few lines above, unconnected to anything.
console.log("\n[3. memo rule, compiler-verified] every builder call sits inside a useMemo factory");
{
  const sf = ts.createSourceFile(
    FILES.vaultPage,
    src.vaultPage,
    ts.ScriptTarget.ESNext,
    /* setParentNodes */ true,
    ts.ScriptKind.TSX,
  );

  function findCalls(root: ts.Node, calleeName: string): ts.CallExpression[] {
    const out: ts.CallExpression[] = [];
    const visit = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && n.expression.getText(sf) === calleeName) out.push(n);
      ts.forEachChild(n, visit);
    };
    visit(root);
    return out;
  }

  /** Walk up the parent chain from `call` looking for an enclosing
   *  `useMemo(factory, deps)` whose FIRST ARGUMENT spans `call` - i.e. `call`
   *  is actually inside the memoized function, not merely inside the same
   *  statement or a neighbouring dependency array. */
  function insideUseMemoFactory(call: ts.CallExpression): boolean {
    for (let cur: ts.Node | undefined = call.parent; cur; cur = cur.parent) {
      if (ts.isCallExpression(cur) && cur.expression.getText(sf) === "useMemo") {
        const factory = cur.arguments[0];
        if (factory && call.getStart(sf) >= factory.getStart(sf) && call.end <= factory.end) {
          return true;
        }
      }
    }
    return false;
  }

  for (const name of ["identityRows", "keyRows", "rankIdentities", "rankKeys"]) {
    const calls = findCalls(sf, name);
    check(`found exactly one \`${name}(\` call to check`, calls.length === 1, calls.length);
    for (const call of calls) {
      check(
        `${name}(...) is called from inside a useMemo(...) factory`,
        insideUseMemoFactory(call),
        call.getText(sf),
      );
    }
  }
}

// ============================================================================
// 4. No row builder is inside a selector.
// ============================================================================
// Protects: the same "Maximum update depth exceeded" failure mode, from the
// other direction - a selector (`useStore((s) => ...)`, or `useShallow`, which
// appears nowhere in `src/` today) calling one of the row builders directly.
// Kept simple and negative, per the plan.
console.log("\n[4. no selector] the page reads useVault()/useHosts(), it does not select");
check("VaultPage.tsx does not import/use useShallow", !src.vaultPage.includes("useShallow"));
check("VaultPage.tsx has no useStore( call", !/useStore\(/.test(src.vaultPage));

// ============================================================================
// 5. The identity delete hands the store the injected lookup.
// ============================================================================
// Protects: `identityHostRefs` is the ONE place that answers "which hosts
// bind this identity" - an inline `(id) => [...]` here would be a second,
// silently-divergent implementation of that same question.
console.log("\n[5. injected lookup] deleteIdentity is called with the shared identityHostRefs");
{
  const v = src.vaultPage;
  check(
    "deleteIdentity(<id>, identityHostRefs) - the shared lookup, passed by name",
    /deleteIdentity\(\s*[^,)]+,\s*identityHostRefs\s*\)/.test(v),
  );
  check(
    'imports identityHostRefs from "@/modules/hosts/store"',
    /from "@\/modules\/hosts\/store"/.test(v) && /identityHostRefs/.test(v),
  );
  check(
    "NEGATIVE: no inline (identityId) => ... lookup passed to deleteIdentity",
    !/deleteIdentity\(\s*[^,)]+,\s*\(\s*identityId\s*\)/.test(v),
  );
  check(
    "NEGATIVE: no inline async (...) => ... lookup passed to deleteIdentity",
    !/deleteIdentity\(\s*[^,)]+,\s*async\s*\(/.test(v),
  );
}

// ============================================================================
// 6. Deletes are confirmed, and only from one place. (COMPILER API)
// ============================================================================
// Protects: a card that could delete on its own, without the confirm dialog in
// between - M5 moves exactly that mutation (a `deleteKey(...)` call into a
// card's `onDelete` arrow) and this section is what catches it, because the
// call would then sit outside `confirmDelete`'s body in the syntax tree, no
// matter how visually close it ends up to the rest of the file.
console.log(
  "\n[6. confirmed deletes, compiler-verified] every delete call is inside confirmDelete",
);
{
  const sf = ts.createSourceFile(
    FILES.vaultPage,
    src.vaultPage,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );

  /** The factory function handed to `useCallback` in `const <name> =
   *  useCallback(fn, deps)`, or `null` if that shape is not found. */
  function useCallbackFactory(root: ts.Node, name: string): ts.Node | null {
    let result: ts.Node | null = null;
    const visit = (n: ts.Node): void => {
      if (
        ts.isVariableDeclaration(n) &&
        ts.isIdentifier(n.name) &&
        n.name.text === name &&
        n.initializer &&
        ts.isCallExpression(n.initializer) &&
        n.initializer.expression.getText(sf) === "useCallback"
      ) {
        const fn = n.initializer.arguments[0];
        if (fn) result = fn;
      }
      ts.forEachChild(n, visit);
    };
    visit(root);
    return result;
  }

  function findCalls(root: ts.Node, calleeNames: string[]): ts.CallExpression[] {
    const out: ts.CallExpression[] = [];
    const visit = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && calleeNames.includes(n.expression.getText(sf))) out.push(n);
      ts.forEachChild(n, visit);
    };
    visit(root);
    return out;
  }

  const confirmDelete = useCallbackFactory(sf, "confirmDelete");
  check("found confirmDelete's useCallback factory", confirmDelete !== null);

  const deleteCalls = findCalls(sf, ["deleteIdentity", "deleteKey"]);
  check(
    "found at least one deleteIdentity/deleteKey call",
    deleteCalls.length > 0,
    deleteCalls.length,
  );
  if (confirmDelete) {
    for (const call of deleteCalls) {
      const inside =
        call.getStart(sf) >= confirmDelete.getStart(sf) && call.end <= confirmDelete.end;
      check(`${call.getText(sf)} is lexically inside confirmDelete`, inside, call.getText(sf));
    }
  }

  for (const key of ["identityCard", "keyCard"] as const) {
    check(
      `${FILES[key]} contains no deleteIdentity/deleteKey call of its own`,
      !/delete(Identity|Key)\(/.test(src[key]),
    );
    check(
      `${FILES[key]} does not import from ../store`,
      !/from ["']\.\.\/store["']/.test(src[key]),
    );
  }
}

// ============================================================================
// 7. The refusal goes to the shared toast; the page has no error surface of
//    its own.
// ============================================================================
// Protects: VLT-36's still-unfinished half - a page-owned `useState<string |
// null>` (or a hand-rolled `role="alert"` line) that never expires, instead of
// the shared, self-expiring `toast()`.
console.log("\n[7. one error surface] the refusal reaches toast(), and nowhere else");
{
  const v = src.vaultPage;
  check(
    "toast(deleteRefusalText(...)) - tolerates both one-line and multi-line call shapes",
    /toast\(\s*deleteRefusalText\(/.test(v),
  );
  check(
    'imports toast from "@/components/ui/toast"',
    /import\s*\{\s*toast\s*\}\s*from\s*"@\/components\/ui\/toast";/.test(v),
  );
  for (const smell of ["setError", "useState<string | null>", 'role="alert"']) {
    check(`no \`${smell}\` in VaultPage.tsx`, !v.includes(smell));
  }
}

// ============================================================================
// 8. The page keeps its own search box, with both narrow rules.
// ============================================================================
// Protects: the element exists and is unique. The WIDTH BEHAVIOUR itself -
// `@max-[420px]:basis-full` / `@max-[420px]:min-w-40` - is
// `scripts/hosts-header-narrow-verify.ts`'s job, forcing the container width
// directly; this section only proves there is one search box here for that
// script (and this one) to be checking in the first place.
console.log("\n[8. search box] exactly one, with its placeholder and label");
{
  const v = src.vaultPage;
  const matches = v.match(/<InputGroup /g) ?? [];
  check("exactly one <InputGroup ...> in VaultPage.tsx", matches.length === 1, matches.length);
  check('placeholder="Search vault…" present', v.includes('placeholder="Search vault…"'));
  check('aria-label="Search vault" present', v.includes('aria-label="Search vault"'));
}

// ============================================================================
// 9. Container queries, not viewport breakpoints.
// ============================================================================
// Protects: this page renders inside the workspace column, whose width comes
// from the sidebar drag and the right slot, never the window - so a viewport
// breakpoint here is wrong at every window size where the pane and the window
// disagree. Runs over the three NEW files (not `RailViewArea.tsx`, which
// carries no layout of its own).
console.log("\n[9. @container, not sm:/md:/lg:/xl:/2xl:] no viewport breakpoints anywhere new");
for (const key of NEW_FILES) {
  check(`${FILES[key]} has no viewport breakpoint`, !/\b(sm|md|lg|xl|2xl):/.test(src[key]));
}
check("VaultPage.tsx uses @container", src.vaultPage.includes("@container"));

// ============================================================================
// 10. content-visibility comes with its floor.
// ============================================================================
// Protects: without `contain-intrinsic-size`, an off-screen card lays out at
// 0px and the scrollbar jumps while the user scrolls - the pair is
// load-bearing, and M7 deletes exactly the half that is easy to drop by
// accident.
console.log("\n[10. content-visibility + its floor] both halves, on both cards");
for (const key of ["identityCard", "keyCard"] as const) {
  check(
    `${FILES[key]} has [content-visibility:auto]`,
    src[key].includes("[content-visibility:auto]"),
  );
  check(
    `${FILES[key]} has [contain-intrinsic-size:auto_100px]`,
    src[key].includes("[contain-intrinsic-size:auto_100px]"),
  );
}

// ============================================================================
// 11. The key card's record prop is not called `key`.
// ============================================================================
// Protects: `key` is React's reserved prop name - a prop literally named `key`
// never reaches the component. Checked from BOTH ends: the card's own prop
// type, and the page's two separate uses of the list key and the record prop.
console.log("\n[11. vaultKey, not key] the reserved prop name is avoided on both sides");
{
  const k = src.keyCard;
  check("KeyCard.tsx declares `vaultKey: VaultKey`", /vaultKey: VaultKey/.test(k));
  check("KeyCard.tsx's props do not declare a `key:` field", !/\bkey:/.test(k));

  const v = src.vaultPage;
  check("VaultPage.tsx passes vaultKey={row.key}", /vaultKey=\{row\.key\}/.test(v));
  check(
    "VaultPage.tsx's <KeyCard> also carries the LIST key key={row.key.id}",
    /<KeyCard[\s\S]{0,120}key=\{row\.key\.id\}/.test(v),
  );
}

// ============================================================================
// 12. Nothing claims a secret is safe.
// ============================================================================
// Protects: nothing in this wave protects a secret better than it was
// protected before - what a shared identity buys is fewer COPIES of one
// secret, never a stronger guarantee, and the copy must not imply otherwise.
// NOTE: "Encrypted" is deliberately NOT forbidden here - wave 3's key panel
// says it about a locked key, truthfully, and that is a different claim.
console.log(
  '\n[12. no false safety claim] "safer"/"securely"/"OS keychain" etc. appear nowhere new',
);
for (const key of NEW_FILES) {
  check(
    `${FILES[key]} does not name a specific secret store`,
    !/OS keychain|Credential Manager/.test(src[key]),
  );
  check(
    `${FILES[key]} makes no safety comparison`,
    !/\bsafer\b|\bsecurely\b|\bmore secure\b/i.test(src[key]),
  );
}

// ============================================================================
// 13. Both empty states are two-way.
// ============================================================================
// Protects: "there is nothing here" and "your query excludes everything" are
// different facts and need different next steps - a single message for both
// is the defect this catches (M10 collapses them to one).
//
// The four literal strings are NECESSARY but not SUFFICIENT: they are also
// present as PROP VALUES at the two `<SectionEmpty>` call sites regardless of
// whether its render logic ever reads `noMatch` - collapsing
// `matching ? noMatch : nothingYet` to always `nothingYet` leaves every one
// of the four literals sitting in the file, byte for byte, while the two
// failure states read identically on screen. The first draft of this section
// checked only the four literals and went GREEN over exactly that mutation
// (M10) - a positive assertion the dead branch can satisfy, the same class
// `pane-caret-verify.ts`'s header warns about. So the render logic itself is
// checked too, via the compiler API: `SectionEmpty`'s function body must
// contain the literal ternary shape, not just the two identifiers somewhere
// in scope.
console.log("\n[13. two-way empty states] all four messages present, AND actually branched on");
{
  const v = src.vaultPage;
  for (const msg of [
    "No saved identities yet.",
    "No identities match.",
    "No saved keys yet.",
    "No keys match.",
  ]) {
    check(`VaultPage.tsx contains "${msg}"`, v.includes(msg));
  }

  const sf = ts.createSourceFile(
    FILES.vaultPage,
    v,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  let sectionEmptyBody: string | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === "SectionEmpty" && n.body) {
      sectionEmptyBody = n.body.getText(sf);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  check("found SectionEmpty's function body to check", sectionEmptyBody !== null);
  if (sectionEmptyBody) {
    check(
      "SectionEmpty's headline actually branches: `matching ? noMatch : nothingYet`",
      /matching\s*\?\s*noMatch\s*:\s*nothingYet/.test(sectionEmptyBody),
      sectionEmptyBody,
    );
  }
}

// ============================================================================
// 14. No dead affordance.
// ============================================================================
// Protects: a button that opens nothing is the dead-affordance class already
// filed against this app once. Wave 3 deletes items off this list as it
// implements them, deliberately.
console.log("\n[14. no dead affordance] no button/prop for something this wave does not implement");
for (const label of ["New identity", "New key", "Edit", "Export", "Import"]) {
  check(`VaultPage.tsx contains no "${label}" string`, !src.vaultPage.includes(label));
}
for (const key of ["identityCard", "keyCard"] as const) {
  for (const prop of ["onEdit", "onSelect", "onConnect"]) {
    check(`${FILES[key]} declares no ${prop} prop`, !src[key].includes(prop));
  }
}

console.log(failed === 0 ? "\nAll vault-shell checks passed." : `\n${failed} check(s) FAILED.`);

// ----------------------------------------------------------------------------
// Mutation table - every mutation actually run against this file's own
// checks, by hand, before this file was considered done. Restored by hash
// each time (`git hash-object` / `git cat-file blob`), never by `git checkout
// --` or `git show HEAD:` (HEAD is wave 2 step 1/2's baseline and would
// discard uncommitted work in the same file). Full transcript, exit codes and
// restore hashes: /tmp/wave2-shell/MUTATIONS.md.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   M1: RailViewArea.tsx's vault case reverted to      section 1's first two
//     <PagePlaceholder page="vault" />                  checks
//   M2: RailViewArea.tsx's forwards case changed to    section 1's third check
//     <VaultPage /> (negative-control check)             (the negative control)
//   M3: identityRows(...) hoisted out of its useMemo   section 3, naming
//     into the render body                              identityRows(...)
//   M4: deleteIdentity(target.id, async () => [])      section 5, both the
//     - an inline lookup instead of identityHostRefs     positive regex and the
//                                                        "async (" negative
//   M5: a deleteKey(row.key.id) call moved into a       section 6, naming that
//     card's onDelete arrow, outside confirmDelete       call as outside
//                                                        confirmDelete's span
//   M6: the .catch changed to                           section 7's toast(
//     .catch((e) => console.error(e))                    deleteRefusalText(
//                                                        check
//   M7: [contain-intrinsic-size:auto_100px] deleted     section 10, for
//     from IdentityCard.tsx                              identityCard only
//   M8: KeyCard's `vaultKey` prop renamed to `key`      section 11, both the
//     (and VaultPage's call site updated to match)        `vaultKey: VaultKey`
//                                                        check and the `key:`
//                                                        negative
//   M9: "Stored securely in the OS keychain." added     section 12, both the
//     to the delete description                          keychain-name and the
//                                                        safety-word checks
//   M10: SectionEmpty made to always render              section 13's ternary
//     `nothingYet`, collapsing the two cases              check ("actually
//     (`{nothingYet}` instead of                          branches on"),
//     `{matching ? noMatch : nothingYet}`)                 naming the broken
//                                                        function body. NOT the
//                                                        four-literal checks:
//                                                        those stayed green,
//                                                        because `noMatch` and
//                                                        `nothingYet` are still
//                                                        passed as PROP VALUES
//                                                        at both call sites
//                                                        regardless of whether
//                                                        the render logic ever
//                                                        reads `noMatch` - the
//                                                        first draft of section
//                                                        13 checked only the
//                                                        four literals and this
//                                                        mutation went GREEN
//                                                        over it. The ternary
//                                                        check (compiler API,
//                                                        over SectionEmpty's own
//                                                        function body) is what
//                                                        was added to catch it.
process.exit(failed === 0 ? 0 : 1);
