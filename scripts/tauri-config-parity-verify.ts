/**
 * Self-check for the `app.windows[0]` entry across the three Tauri config
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
 * That is exactly how the window floor went missing:
 * `minWidth`/`minHeight` lived only in the base file, so only macOS (which
 * has no override file) ever got a floor. `title` and `visible` were hit the
 * same way before they were restated on both platforms.
 *
 * This check reads all three files off disk - not an inlined copy of their
 * contents, which would be the same disease as the bug it exists to catch -
 * and applies two different rules, because there are two different failure
 * modes:
 *
 *   PRESENCE, for every key of the base `windows[0]`. A base-only key that an
 *   override drops is never a decision, it is a silent schema default. And
 *   presence is all that can be demanded of the keys a platform legitimately
 *   tunes - `title`, `decorations`, `transparent`, `shadow` - where carrying a
 *   different value is the merge model working as intended, not a bug.
 *
 *   VALUE EQUALITY, for GEOMETRY_KEYS. The floor's actual damage was a *value*
 *   silently not applying, and presence cannot see that shape at all: revert
 *   `minWidth` to its old number in both override files and every key is still
 *   present, while both shipping platforms get the old floor. Geometry has no
 *   platform-specific right answer here - the floor is a property of what the
 *   UI needs in order to render (an 80x24 terminal), not of the window
 *   manager - so the three files must agree digit for digit.
 *
 * The geometry keys are additionally asserted to EXIST in the base. Without
 * that, the per-key loop is driven entirely by the base's own key set, so
 * trimming the base silently shrinks the check along with it: deleting
 * `minWidth` from the base takes the floor away from macOS while every
 * remaining assertion still passes, and an emptied `windows[0]` would run zero
 * assertions and print a pass. That is the empty-fold shape, and
 * declaring the set up front is what closes it.
 *
 * `bundle.targets` is the other base array that both platform files redeclare.
 * That divergence is deliberate - each platform builds its own installer set -
 * and has no live defect, so it is out of scope here on purpose.
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

/**
 * Keys whose VALUE must match across all three files, and which the base must
 * declare. Window size and the size floor: no platform has a reason to differ,
 * and a divergence here is the floor silently not applying, not customization.
 */
const GEOMETRY_KEYS = ["width", "height", "minWidth", "minHeight"] as const;

const base = firstWindow(BASE_PATH);
const overrides: ReadonlyArray<readonly [string, WindowConfig]> = [
  [LINUX_PATH, firstWindow(LINUX_PATH)],
  [WINDOWS_PATH, firstWindow(WINDOWS_PATH)],
];

console.log("[base declares] the geometry set exists in the base, so nothing below is vacuous");
for (const key of GEOMETRY_KEYS) {
  check(`${BASE_PATH} declares "${key}"`, key in base && base[key] !== null, true);
}

console.log("\n[key parity] every base app.windows[0] key survives the platform merge");
for (const key of Object.keys(base)) {
  for (const [path, override] of overrides) {
    check(`${path} restates "${key}"`, key in override, true);
  }
}

console.log("\n[geometry value] size and size floor are identical in all three files");
for (const key of GEOMETRY_KEYS) {
  for (const [path, override] of overrides) {
    check(`${path} "${key}" matches the base`, override[key], base[key]);
  }
}

console.log(
  failed === 0 ? "\nAll tauri-config-parity checks passed." : `\n${failed} check(s) FAILED.`,
);
process.exit(failed === 0 ? 0 : 1);
