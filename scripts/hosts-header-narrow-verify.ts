/**
 * Self-check for the page header row pattern - the Hosts page, and the Vault
 * page that reuses it verbatim by decision - at a FORCED container width, and
 * the search box's wrap rule specifically.
 * Run: `pnpm verify hosts-header-narrow` (or `npx tsx
 * scripts/hosts-header-narrow-verify.ts` to iterate).
 *
 * There is no DOM or layout engine anywhere in this repo's check suite - no
 * jsdom, no playwright, nothing in `devDependencies` that can compute CSS
 * (`scripts/*-verify.ts` all run under plain `tsx`, see `verify-all.mjs`) -
 * and a `@container` breakpoint needs real layout to resolve, so rendering
 * `HostsPage` here could not answer "what does the header look like at
 * 400px" the way a browser would. What CAN be answered from plain text is
 * the one thing a `@container` variant actually promises: which of a class
 * string's `@max-[Npx]:` / `@[Npx]:` utilities are active at a given width.
 * `activeAt` below is a tiny, deliberately narrow simulator of exactly that
 * - not a general Tailwind engine, just the two variant forms this header
 * uses - run against the ACTUAL className strings pulled out of the two
 * source files by anchored regex, so a class renamed or removed there fails
 * this file loudly instead of the check silently drifting from what ships.
 *
 * Why this file exists at all: every size floor
 * between this pane and the window edge - the sidebar, this workspace
 * column, the right slot, a pane split - is a PERCENTAGE, not a px minimum
 * (see the `@container` comment on `HostsPage`'s root div for the full list
 * and file:line references), so a percentage floor shrinks right along with
 * the window and a divider drag can never push a pane's CSS width under the
 * 420px this header's narrow layout keys off, AT ANY WINDOW WIDTH WIDE
 * ENOUGH TO BE USABLE - confirmed by hand at both divider stops across four
 * window widths, landing on an emergent floor (25% of whatever window width
 * was in use), not a constant. The header's `@container` rules, and the wrap
 * rule on the search box specifically, are therefore not reachable by
 * hand-resizing anything in a running build - only by shrinking the WINDOW
 * itself down toward its own floor (`tauri.conf.json`'s `minWidth: 640`,
 * the same order of magnitude as this breakpoint). TWO DIFFERENT NUMBERS
 * THAT BOTH READ 420 ONCE: the 420 this file checks is the header's own
 * CONTAINER breakpoint and is correct everywhere it appears below; the
 * window floor is the config's, and it is 640. This file, forcing the
 * width directly instead of asking a real pane to reach it, is the only
 * verification either one gets.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let failed = 0;
function check(label: string, cond: boolean): void {
  if (cond) console.log(`  ok: ${label}`);
  else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

// --- a narrow, explicit simulator for the two variant forms this header uses ---

/**
 * Which of `classNames`' utilities apply at `widthPx` container width.
 *   `@max-[Npx]:utility` -> active when widthPx <= N
 *   `@[Npx]:utility`     -> active when widthPx >= N
 *   a plain utility (no `@` prefix) is always active
 * A token using a variant form this header does not use (`@min-`, a named
 * breakpoint like `sm:`, ...) does not match the regex below and falls
 * through to "plain utility", added to the set under its own literal text
 * (e.g. `"sm:hidden"`) rather than the bare utility it would apply. That
 * reads as "never seen" to every `.has("hidden")` check below - a
 * deliberate under-approximation (fail the check, don't guess the variant's
 * meaning) rather than a silent wrong answer.
 */
function activeAt(classNames: string, widthPx: number): Set<string> {
  const active = new Set<string>();
  for (const token of classNames.trim().split(/\s+/).filter(Boolean)) {
    const m = /^@(max-)?\[(\d+)px]:(.+)$/.exec(token);
    if (!m) {
      active.add(token);
      continue;
    }
    const [, isMax, pxStr, utility] = m;
    const px = Number(pxStr);
    const applies = isMax ? widthPx <= px : widthPx >= px;
    if (applies) active.add(utility);
  }
  return active;
}

/** Anchored extraction, reported as its own check so a renamed anchor is a
 *  visible FAIL here rather than an empty string quietly satisfying every
 *  later `activeAt(...).has(...)` check by having nothing to match against. */
function findClass(src: string, re: RegExp, label: string): string {
  const m = re.exec(src);
  check(`anchor found: ${label}`, m !== null);
  return m ? m[1] : "";
}

// --- pull the real className strings out of the real source files ---

const hostsPageSrc = read("src/modules/hosts/HostsPage.tsx");
const backupActionsSrc = read("src/modules/hosts/page/HostsBackupActions.tsx");
const vaultPageSrc = read("src/modules/vault/VaultPage.tsx");

const headerRowClass = findClass(
  hostsPageSrc,
  /<div className="(flex flex-wrap items-center gap-2)">/,
  "header controls row (New host / protocol / search / backup actions)",
);
const newHostLabelClass = findClass(
  hostsPageSrc,
  /<span className="([^"]*)">New host<\/span>/,
  "New host button label",
);
const protocolGroupClass = findClass(
  hostsPageSrc,
  /className="([^"]*)"\s*\n\s*role="group"\s*\n\s*aria-label="Protocol"/,
  "protocol chip group wrapper",
);
const searchInputGroupClass = findClass(
  hostsPageSrc,
  /<InputGroup className="([^"]*)">\s*\n\s*<InputGroupAddon>\s*\n\s*<Search \/>/,
  "search InputGroup",
);
const vaultSearchInputGroupClass = findClass(
  vaultPageSrc,
  /<InputGroup className="([^"]*)">\s*\n\s*<InputGroupAddon>\s*\n\s*<Search \/>/,
  "Vault page search InputGroup",
);
check(
  "exactly one InputGroup in VaultPage.tsx",
  (vaultPageSrc.match(/<InputGroup /g) ?? []).length === 1,
);
const forwardsPageSrc = read("src/modules/forwards/ForwardsPage.tsx");
const forwardsSearchInputGroupClass = findClass(
  forwardsPageSrc,
  /<InputGroup className="([^"]*)">\s*\n\s*<InputGroupAddon>\s*\n\s*<Search \/>/,
  "Port Forwarding page search InputGroup",
);
check(
  "exactly one InputGroup in ForwardsPage.tsx",
  (forwardsPageSrc.match(/<InputGroup /g) ?? []).length === 1,
);
const newIdentityLabelClass = findClass(
  vaultPageSrc,
  /<span className="([^"]*)">New identity<\/span>/,
  "New identity button label",
);
const newKeyLabelClass = findClass(
  vaultPageSrc,
  /<span className="([^"]*)">New key<\/span>/,
  "New key button label",
);
const exportLabelClass = findClass(
  backupActionsSrc,
  /<span className="([^"]*)">Export…<\/span>/,
  "Export… button label",
);
const importLabelClass = findClass(
  backupActionsSrc,
  /<span className="([^"]*)">Import…<\/span>/,
  "Import… button label",
);

// Exactly one InputGroup on this page - if a second one is ever added, the
// regex above could start matching the wrong one silently.
check(
  "exactly one InputGroup in HostsPage.tsx",
  (hostsPageSrc.match(/<InputGroup /g) ?? []).length === 1,
);

// --- the header row itself always wraps, at any width ---

console.log("\n[header row] flex-wrap is unconditional, not itself a @container rule");
check("flex-wrap present at 300px", activeAt(headerRowClass, 300).has("flex-wrap"));
check("flex-wrap present at 1400px", activeAt(headerRowClass, 1400).has("flex-wrap"));

// --- New host / Export / Import collapse to icon-only at <=420px ---

console.log("\n[collapse] New host / Export… / Import… labels hide at <=420px, show above it");
for (const [label, cls] of [
  ["New host", newHostLabelClass],
  ["Export…", exportLabelClass],
  ["Import…", importLabelClass],
] as const) {
  check(`${label} label hidden at 400px`, activeAt(cls, 400).has("hidden"));
  check(`${label} label hidden at 420px (boundary, inclusive)`, activeAt(cls, 420).has("hidden"));
  check(`${label} label visible at 421px`, !activeAt(cls, 421).has("hidden"));
  check(`${label} label visible at 1200px`, !activeAt(cls, 1200).has("hidden"));
}

// --- protocol chip group: unconditional wrap, no @container gating ---

console.log("\n[protocol group] wraps internally at any width, per HostsPage.tsx's own comment");
check("min-w-0 present at 300px", activeAt(protocolGroupClass, 300).has("min-w-0"));
check("flex-wrap present at 300px", activeAt(protocolGroupClass, 300).has("flex-wrap"));
check("flex-wrap present at 1400px", activeAt(protocolGroupClass, 1400).has("flex-wrap"));

// --- the search box has BOTH a wrap rule and a min-width floor ---------------

console.log("\n[search box] a wrap rule AND a min-width floor at <=420px");
{
  const at400 = activeAt(searchInputGroupClass, 400);
  check("basis-full (wrap rule) active at 400px", at400.has("basis-full"));
  check("min-w-40 (floor) active at 400px", at400.has("min-w-40"));

  const at420 = activeAt(searchInputGroupClass, 420);
  check("basis-full active at the 420px boundary (inclusive)", at420.has("basis-full"));
  check("min-w-40 active at the 420px boundary (inclusive)", at420.has("min-w-40"));

  const at421 = activeAt(searchInputGroupClass, 421);
  check("basis-full NOT active at 421px (wrap rule is <=420 only)", !at421.has("basis-full"));
  // The 420-480px band is a pre-existing, documented gap (see the comment on
  // this InputGroup in HostsPage.tsx) - not what the wrap rule was added for,
  // and not widened or narrowed by it. Pinned here so a future change to either
  // boundary has to touch this check on purpose.
  check("min-w-40 NOT active at 421px (the pre-existing 420-480px gap)", !at421.has("min-w-40"));

  const at480 = activeAt(searchInputGroupClass, 480);
  check("min-w-40 active again at 480px (the original @[480px] floor)", at480.has("min-w-40"));
  check("basis-full NOT active at 480px (no longer wrapping)", !at480.has("basis-full"));

  const at1200 = activeAt(searchInputGroupClass, 1200);
  check("min-w-40 active at 1200px", at1200.has("min-w-40"));
  check("basis-full NOT active at 1200px", !at1200.has("basis-full"));
}

// --- the desktop arrow convention, and the only check on it -----------------

console.log("\n[icons] Export points OUT of the box, Import points IN");
{
  // Two live conventions exist - the web-form one ("download the result" /
  // "upload your file") is what shipped, and the desktop one is the reverse -
  // so this was never a defect and is not self-evident from reading the file.
  // Which means: without a check, the next person to touch these two buttons flips
  // them back on instinct and nothing notices. Lucide's `Upload` is an arrow
  // leaving a tray (data going OUT = Export); `Download` is an arrow entering
  // one (data coming IN = Import).
  //
  // Anchored to the button each icon sits in, not to the import list: both
  // names stay imported either way, so an import-list check cannot tell the
  // swap from the pre-swap state.
  const exportButton = findClass(
    backupActionsSrc,
    /aria-label="Export…"([\s\S]{0,400}?)<span className="[^"]*">Export…<\/span>/,
    "Export… button body",
  );
  const importButton = findClass(
    backupActionsSrc,
    /aria-label="Import…"([\s\S]{0,400}?)<span className="[^"]*">Import…<\/span>/,
    "Import… button body",
  );
  check("Export renders <Upload> (arrow out)", /<Upload\b/.test(exportButton));
  check("...and not <Download>", !/<Download\b/.test(exportButton));
  check("Import renders <Download> (arrow in)", /<Download\b/.test(importButton));
  check("...and not <Upload>", !/<Upload\b/.test(importButton));
}

// --- the Vault page reuses that header verbatim -----------------------------

console.log("\n[vault header] the same wrap rule and floor, on the second page that has one");
{
  // ONE check for the whole pattern, because "reused as-is" is the decision:
  // three adjacent unlabelled search fields was accepted on the condition that
  // the Vault page copies this header rather than re-deriving it. If a later
  // change needs them to differ, it has to change this line on purpose.
  //
  // The search box's `@max-[420px]:basis-full` rule is load-bearing on this
  // page rather than merely inherited: below 420px the two buttons sharing its
  // row (New identity, New key) shed their labels but stay on the first row,
  // and the wrap rule is what claims a full row for the search box instead of
  // leaving it squeezed between them.
  check(
    "the Vault page's search box carries the identical className string",
    vaultSearchInputGroupClass === searchInputGroupClass,
  );

  // And the same width assertions anyway, so this section still says something
  // if that equality is ever deliberately relaxed.
  const vaultAt400 = activeAt(vaultSearchInputGroupClass, 400);
  check("basis-full (wrap rule) active at 400px", vaultAt400.has("basis-full"));
  check("min-w-40 (floor) active at 400px", vaultAt400.has("min-w-40"));
  const vaultAt420 = activeAt(vaultSearchInputGroupClass, 420);
  check(
    "both active at the 420px boundary (inclusive)",
    vaultAt420.has("basis-full") && vaultAt420.has("min-w-40"),
  );
  const vaultAt421 = activeAt(vaultSearchInputGroupClass, 421);
  check("basis-full NOT active at 421px", !vaultAt421.has("basis-full"));
  check(
    "min-w-40 NOT active at 421px (the same pre-existing 420-480px gap)",
    !vaultAt421.has("min-w-40"),
  );
  const vaultAt480 = activeAt(vaultSearchInputGroupClass, 480);
  check("min-w-40 active again at 480px", vaultAt480.has("min-w-40"));
  check("basis-full NOT active at 480px", !vaultAt480.has("basis-full"));

  // The two new header buttons collapse to icon-only at the same threshold
  // the Hosts page's New host button and the two backup buttons use.
  for (const [label, cls] of [
    ["New identity", newIdentityLabelClass],
    ["New key", newKeyLabelClass],
  ] as const) {
    check(`${label} label hidden at 400px`, activeAt(cls, 400).has("hidden"));
    check(`${label} label hidden at 420px (boundary, inclusive)`, activeAt(cls, 420).has("hidden"));
    check(`${label} label visible at 421px`, !activeAt(cls, 421).has("hidden"));
    check(`${label} label visible at 1200px`, !activeAt(cls, 1200).has("hidden"));
  }
}

// --- the Port Forwarding page reuses the same header too -------------------

console.log("\n[forwards header] the same wrap rule and floor, on the third page that has one");
{
  // Three-way, not just a second pairwise check: the Vault equality above
  // stays its OWN check (so a failure names which page drifted) and this adds
  // the forwards page as its own leg, so a break in either pairing is
  // reported against the right page rather than a single combined "one of
  // three disagrees" line. Three adjacent unlabelled search fields was
  // accepted on the condition that every later page copies this
  // header rather than re-deriving it - a later page has to diverge on
  // purpose (K1/K2 name exactly that: a change to only the forwards copy
  // breaks this equality; a change to all three together does not, because
  // the equality is a PARITY check, not a restatement of the literal).
  check(
    "the Port Forwarding page's search box carries the identical className string",
    forwardsSearchInputGroupClass === searchInputGroupClass,
  );

  const forwardsAt400 = activeAt(forwardsSearchInputGroupClass, 400);
  check("basis-full (wrap rule) active at 400px", forwardsAt400.has("basis-full"));
  check("min-w-40 (floor) active at 400px", forwardsAt400.has("min-w-40"));
  const forwardsAt420 = activeAt(forwardsSearchInputGroupClass, 420);
  check(
    "both active at the 420px boundary (inclusive)",
    forwardsAt420.has("basis-full") && forwardsAt420.has("min-w-40"),
  );
  const forwardsAt421 = activeAt(forwardsSearchInputGroupClass, 421);
  check("basis-full NOT active at 421px", !forwardsAt421.has("basis-full"));
  check(
    "min-w-40 NOT active at 421px (the same pre-existing 420-480px gap)",
    !forwardsAt421.has("min-w-40"),
  );
  const forwardsAt480 = activeAt(forwardsSearchInputGroupClass, 480);
  check("min-w-40 active again at 480px", forwardsAt480.has("min-w-40"));
  check("basis-full NOT active at 480px", !forwardsAt480.has("basis-full"));
}

// --- gate: what this check would catch, and what it was watched to catch ---
//
// Mutation                                            Check it killed
// ---------------------------------------------------  ---------------------------
// Drop `@max-[420px]:basis-full` from the search box   "basis-full (wrap rule)
//                                                       active at 400px"
// Drop `@max-[420px]:min-w-40` from the search box     "min-w-40 (floor) active
//                                                       at 400px"
// Both of the above at once (full revert to the         Both checks above, plus
//   pre-fix `min-w-0 flex-1 @[480px]:min-w-40`)         the two 420px-boundary ones
// Swap Export/Import icons back to the web-form         All four arrow checks
//   convention (Download on Export, Upload on Import)
// Reorder the `import { Download, Upload }` line while   No change - the four
//   leaving the icons swapped                            arrow checks are anchored
//                                                         to the button body, not
//                                                         the import list
// Delete `@max-[420px]:basis-full` from VaultPage.tsx's  The equality check AND
//   InputGroup                                           the Vault 400px wrap check
// Rename `InputGroup` to `InputGroupX` in VaultPage.tsx  "anchor found: Vault page
//                                                         search InputGroup"
//
// K1 (step 10): change the forwards search           The three-way equality
//   InputGroup's className by one utility only          FAILs, and the width
//   (e.g. drop @max-[420px]:basis-full)                 assertions FAIL at the
//                                                        widths that utility
//                                                        governs
// K2 (step 10): change all THREE search classNames     The equality stays
//   identically (hosts, vault, forwards alike)           GREEN and the width
//                                                        assertions FAIL - the
//                                                        pairing that makes the
//                                                        equality a PARITY
//                                                        check, not a
//                                                        restatement of the
//                                                        literal
//
// The mutate -> red -> restore -> `diff` transcript itself is not kept here,
// because a stale transcript nobody re-runs is worse than no transcript, and
// this file's own gate (the checks above) is what stays true.

console.log(
  failed === 0 ? "\nAll hosts-header-narrow checks passed." : `\n${failed} check(s) FAILED.`,
);
process.exit(failed === 0 ? 0 : 1);
