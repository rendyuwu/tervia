/**
 * Self-check: the Hosts page's three row-action error surfaces
 * route through the shared toast (`components/ui/toast.tsx`) instead of a
 * page-owned, persistent inline line.
 * Run: `pnpm verify hosts-error-toast` (or `npx tsx
 * scripts/hosts-error-toast-verify.ts` to iterate).
 *
 * SOURCE-TEXT, not behavioural: there is no DOM/layout engine in this repo's
 * check suite (see the comment on `hosts-header-narrow-verify.ts`), and the
 * bug this fixes was never about what one call to `toast()` renders - the
 * toast component and its expiry timers already exist and are unchanged -
 * it was about which of three surfaces still had a page-owned `useState`
 * with no lifetime of its own. Only `HostsPage.tsx`'s had an explicit
 * dismiss `×`; `GroupStrip.tsx`'s and `HostsBackupActions.tsx`'s had NONE -
 * cleared only implicitly, at the top of the next same-kind action - which
 * made those two the worse two of the three, not the milder ones. That is a
 * property of the SOURCE (is there still a persistent error state to
 * render, or does every failure path call the shared `toast()`), not of any
 * one render, so a regex over the three files is what actually answers "did
 * the fix apply, and does it apply to all three, not two of three."
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

const FILES = {
  hostsPage: "src/modules/hosts/HostsPage.tsx",
  groupStrip: "src/modules/hosts/page/GroupStrip.tsx",
  backupActions: "src/modules/hosts/page/HostsBackupActions.tsx",
} as const;

const src = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, read(p)])) as Record<
  keyof typeof FILES,
  string
>;

// --- each surface imports the shared toast, not a local error renderer ------

console.log("[import] all three surfaces import the shared toast");
for (const name of Object.keys(FILES)) {
  check(
    `${name} imports toast from @/components/ui/toast`,
    /import\s*\{\s*toast\s*\}\s*from\s*"@\/components\/ui\/toast";/.test(
      src[name as keyof typeof FILES],
    ),
  );
}

// --- no surface still owns a persistent, page-local error string ------------
//
// Named after what THIS page called its own state before the fix
// (`actionError`/`setActionError`, `error`/`setError`, `pickError`/
// `setPickError` - see the pre-fix HostsPage.tsx / GroupStrip.tsx /
// HostsBackupActions.tsx). A generic `/\berror\b/i` sweep would flag the
// legitimate `(e: unknown)` catch parameters and `e instanceof Error`
// checks this file still needs to keep - it is specifically the REACT
// STATE that must be gone, not the word.

console.log("\n[no persistent state] the old page-local error state is gone");
check("HostsPage: no actionError state", !/actionError/.test(src.hostsPage));
check("GroupStrip: no local error state (setError)", !/\bsetError\(/.test(src.groupStrip));
check("HostsBackupActions: no pickError state", !/pickError/.test(src.backupActions));

// --- every failure path that used to set that state now calls toast() ------

console.log('\n[every failure path calls toast(..., { variant: "error" })]');
// HostsPage: the two `duplicate` failure branches and the one `confirmDelete`
// refusal branch.
check(
  "HostsPage duplicate(): the null-copy branch toasts",
  /if \(!copy\) \{\s*\n\s*toast\(`"\$\{host\.name\}" no longer exists, so there was nothing to copy\.`,\s*\{\s*\n\s*variant: "error",/.test(
    src.hostsPage,
  ),
);
check(
  "HostsPage duplicate(): the rejected-promise branch toasts",
  /\.catch\(\(e: unknown\) => toast\(errorText\(e\), \{ variant: "error" \}\)\);/.test(
    src.hostsPage,
  ),
);
check(
  "HostsPage confirmDelete(): the refusal branch toasts the FULL deleteRefusalText",
  /toast\(deleteRefusalText\(host, e\), \{ variant: "error" \}\),/.test(src.hostsPage),
);
// GroupStrip: the one shared runMutation catch.
check(
  "GroupStrip runMutation(): the catch toasts",
  /catch \(e\) \{\s*\n\s*toast\(e instanceof Error \? e\.message : String\(e\), \{ variant: "error" \}\);/.test(
    src.groupStrip,
  ),
);
// HostsBackupActions: the non-text-file branch and the pick/read catch.
check(
  "HostsBackupActions openImport(): the non-UTF-8 branch toasts",
  /toast\("That file is not a UTF-8 text file\.", \{ variant: "error" \}\);/.test(
    src.backupActions,
  ),
);
check(
  "HostsBackupActions openImport(): the catch toasts",
  /catch \(e\) \{\s*\n\s*toast\(e instanceof Error \? e\.message : String\(e\), \{ variant: "error" \}\);/.test(
    src.backupActions,
  ),
);

// --- no surface still renders its own destructive inline line ---------------
//
// The pre-fix shape in all three: a `text-destructive` span/line rendering
// the state variable. Only HostsPage's had its own dismiss `×`; the other
// two had no dismiss control at all. If any of the three still has this
// span, the fix did not reach it, regardless of whether it ALSO now calls
// toast() (a caller could add toast() alongside the old line by mistake,
// leaving the exact bug the toast replaced - a message that never goes away on
// its own - twice, on whichever surface still has the leftover span).

console.log("\n[no leftover inline error line] none of the three still render one of their own");
check(
  "HostsPage: no text-destructive error line left in the header",
  !/text-destructive.*actionError|actionError.*text-destructive/s.test(src.hostsPage),
);
check(
  "GroupStrip: no `{error ? ... text-destructive` line left",
  !/\{error \? <span className="text-destructive/.test(src.groupStrip),
);
check(
  "HostsBackupActions: no `{pickError ? ... text-destructive` line left",
  !/\{pickError \? <span className="text-destructive/.test(src.backupActions),
);

console.log(
  failed === 0 ? "\nAll hosts-error-toast checks passed." : `\n${failed} check(s) FAILED.`,
);
process.exit(failed === 0 ? 0 : 1);
