/**
 * Self-check for the `app.windows[0]` key set across the three Tauri config
 * files. Run: `npx tsx scripts/tauri-config-parity-verify.ts`.
 *
 * Tauri merges `tauri.<platform>.conf.json` into `tauri.conf.json` with an
 * RFC 7396 JSON Merge Patch, and `json_patch` replaces any non-object value
 * outright. `app.windows` is an ARRAY, which RFC 7396 treats as a non-object
 * value, so a platform file's `windows[0]` wholesale REPLACES the base entry
 * rather than merging field by field. Any key that exists only in the base
 * `windows[0]` therefore vanishes on that platform - not with an error, but
 * by quietly falling back to whatever default Tauri picks for an unset field.
 *
 * That is exactly how the window floor (VLT-61 / handoff §4.22) went missing:
 * `minWidth`/`minHeight` lived only in the base file, so only macOS (which
 * has no override file) ever got a floor. `title` and `visible` were hit the
 * same way before they were restated on both platforms.
 *
 * This check reads all three files off disk - not an inlined copy of their
 * contents, which would be the same disease as the bug it exists to catch -
 * and asserts that every key present in the base `windows[0]` is also a key
 * in `tauri.linux.conf.json`'s and `tauri.windows.conf.json`'s `windows[0]`.
 *
 * It checks key PRESENCE, not value equality. A platform file legitimately
 * carrying a different VALUE for a shared key (a different title string, a
 * different width to account for platform chrome) is normal customization
 * that the merge model is built to allow. What must never happen again is a
 * base-only key disappearing because a platform override redeclared the
 * array without it - that is a silent default, not a deliberate choice, and
 * presence is the only thing that check can catch without also outlawing
 * intentional divergence.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

type WindowConfig = Record<string, unknown>;
type TauriConfig = { app?: { windows?: WindowConfig[] } };

function firstWindow(relPath: string): WindowConfig {
  const parsed = JSON.parse(read(relPath)) as TauriConfig;
  const win = parsed.app?.windows?.[0];
  if (!win) throw new Error(`${relPath}: app.windows[0] is missing`);
  return win;
}

const BASE_PATH = "src-tauri/tauri.conf.json";
const LINUX_PATH = "src-tauri/tauri.linux.conf.json";
const WINDOWS_PATH = "src-tauri/tauri.windows.conf.json";

const base = firstWindow(BASE_PATH);
const linux = firstWindow(LINUX_PATH);
const windows = firstWindow(WINDOWS_PATH);

console.log("[key parity] every base app.windows[0] key survives the platform merge");
for (const key of Object.keys(base)) {
  check(`${LINUX_PATH} restates "${key}"`, key in linux, true);
  check(`${WINDOWS_PATH} restates "${key}"`, key in windows, true);
}

console.log(
  failed === 0 ? "\nAll tauri-config-parity checks passed." : `\n${failed} check(s) FAILED.`,
);
process.exit(failed === 0 ? 0 : 1);
