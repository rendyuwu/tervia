/**
 * Self-check for App's `isDisabled` gate, in its two halves.
 *
 *  1. WHICH CHORDS - `isTerminalControlChord` / `isTerminalMetaChord`: the ones
 *     a focused terminal keeps (readline editing, Ctrl+D EOF / screen detach,
 *     Ctrl+I Tab, Ctrl+[ Esc, the tmux/screen prefix) instead of the app's
 *     Mod+letter shortcuts stealing them on Windows/Linux.
 *  2. WHO IS FOCUSED - `ownsRawKeyboard` (`shortcuts/lib/keyboardOwner.ts`).
 *     The half that was never asked: the gate used to test which leaf was
 *     ACTIVE IN THE TAB while its own comment claimed to be about focus, so
 *     Ctrl+W was suppressed with the caret in the tab strip (closing no tab
 *     anywhere, VLT-59) and Ctrl+T / Ctrl+] / Ctrl+[ were eaten by a terminal a
 *     rail view had made invisible (VLT-58). Both halves must hold for the gate
 *     to fire, so both halves get a positive AND a negative case here.
 *
 * Run: `npx tsx scripts/keybindings-terminal-verify.ts`.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { isTerminalControlChord, isTerminalMetaChord } from "../src/modules/shortcuts/shortcuts";
import {
  KEYBOARD_OWNING_SURFACES,
  ownsRawKeyboard,
  type FocusTarget,
} from "../src/modules/shortcuts/lib/keyboardOwner";

type Ev = {
  code: string;
  ctrlKey?: boolean;
  shiftKey?: boolean;
  altKey?: boolean;
  metaKey?: boolean;
};
// Mirrors App's gate: a focused terminal owns bare-Ctrl control codes AND
// bare-Alt meta sequences, so both fall through to xterm.
const ev = (e: Ev) => {
  const k = {
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
    metaKey: false,
    ...e,
  } as KeyboardEvent;
  return isTerminalControlChord(k) || isTerminalMetaChord(k);
};

let failed = 0;
function expect(label: string, e: Ev, want: boolean): void {
  const got = ev(e);
  if (got !== want) {
    console.error(`  FAIL: ${label} = ${got}, want ${want}`);
    failed++;
  } else {
    console.log(`  ok: ${want ? "pass-to-shell" : "keep-app-shortcut"} <- ${label}`);
  }
}

console.log("[bare Ctrl + control-code key] -> reach the shell");
for (const [code, name] of [
  ["KeyD", "Ctrl+D (EOF / screen detach)"],
  ["KeyE", "Ctrl+E (end-of-line)"],
  ["KeyW", "Ctrl+W (kill-word)"],
  ["KeyK", "Ctrl+K (kill-line)"],
  ["KeyL", "Ctrl+L (clear)"],
  ["KeyB", "Ctrl+B (back-char / tmux prefix)"],
  ["KeyA", "Ctrl+A (start-of-line / screen prefix)"],
  ["KeyI", "Ctrl+I (Tab)"],
  ["BracketLeft", "Ctrl+[ (Esc)"],
  ["BracketRight", "Ctrl+] (GS)"],
  ["Backslash", "Ctrl+\\ (SIGQUIT)"],
] as const) {
  expect(name, { code, ctrlKey: true }, true);
}

console.log("\n[bare Alt + letter/digit] readline meta -> reach the shell");
expect("Alt+B (backward-word)", { code: "KeyB", altKey: true }, true);
expect("Alt+F (forward-word)", { code: "KeyF", altKey: true }, true);
expect("Alt+D (kill-word)", { code: "KeyD", altKey: true }, true);
expect("Alt+Z (was word-wrap, now meta-z)", { code: "KeyZ", altKey: true }, true);
expect("Alt+1 (digit-argument)", { code: "Digit1", altKey: true }, true);

console.log("\n[app chords] -> stay active, never stolen from");
expect("Ctrl+Shift+C (copy)", { code: "KeyC", ctrlKey: true, shiftKey: true }, false);
expect("Ctrl+Shift+V (paste)", { code: "KeyV", ctrlKey: true, shiftKey: true }, false);
expect("Ctrl+Shift+X (close terminal)", { code: "KeyX", ctrlKey: true, shiftKey: true }, false);
expect("Ctrl+Tab (next tab)", { code: "Tab", ctrlKey: true }, false);
expect("Ctrl+1 (jump to tab)", { code: "Digit1", ctrlKey: true }, false);
expect("Ctrl+= (zoom in)", { code: "Equal", ctrlKey: true }, false);
expect("Ctrl+, (settings)", { code: "Comma", ctrlKey: true }, false);
expect("Ctrl+Alt+P (new browser tab)", { code: "KeyP", ctrlKey: true, altKey: true }, false);
expect("Shift+Alt+F (format doc)", { code: "KeyF", shiftKey: true, altKey: true }, false);
expect("Cmd+D on macOS (meta, not ctrl)", { code: "KeyD", metaKey: true }, false);
expect("plain D (no modifier)", { code: "KeyD" }, false);

// ---------------------------------------------------------------------------
// The other half of the gate: who is holding the keys.
// ---------------------------------------------------------------------------

/**
 * A line with its trailing `//` comment removed, string literals respected, and
 * the same source with whole-line comments dropped.
 *
 * VLT-33; the canonical copy is in `scripts/host-editor-verify.ts` and this is
 * a deliberate duplicate (these scripts share no module). A character scan
 * rather than a regex, because a `//` inside a string is not a comment and a
 * regex alternation desyncs on the first unbalanced quote, after which it eats
 * real code. This loses the strip for such a line instead - failing towards
 * KEEPING text, which is the safe direction for a positive check.
 */
function stripLineComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if (c === "/" && line[i + 1] === "/") return line.slice(0, i);
  }
  return line;
}

function stripComments(src: string): string {
  return src
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
}

function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

/**
 * A focus target that answers `closest` for exactly the selectors a real
 * ancestor of it would match. Stands in for the DOM: `ownsRawKeyboard` takes
 * anything with `closest`, precisely so the deciding half of the rule can be
 * run without jsdom - a real keydown-through-a-mounted-xterm test is stronger
 * and this repo has no renderer for one.
 */
function focusedInside(...markers: string[]): FocusTarget {
  return {
    closest(selectors: string) {
      // Mirrors how a browser reads a comma-separated selector list: a match on
      // ANY of its parts is a match. Splitting here is what makes the fixture
      // sensitive to the selector losing one of its two markers.
      const wanted = selectors.split(",").map((s) => s.trim());
      return markers.some((m) => wanted.includes(`[${m}]`)) ? { marker: markers[0] } : null;
    },
  };
}

console.log("\n[who owns the keyboard] the gate applies only to a focused terminal / RDP pane");
check(
  "focus inside a terminal pane owns the raw keyboard",
  ownsRawKeyboard(focusedInside("data-terminal-leaf-id")),
);
check(
  // VLT-62's sibling: an RDP pane owns Ctrl and Alt exactly as a terminal does,
  // so the selector has to name it too or every bare-Ctrl chord fires an app
  // action instead of reaching the remote desktop.
  "focus inside an RDP pane owns it too",
  ownsRawKeyboard(focusedInside("data-rdp-leaf-id")),
);
check(
  // THE NEGATIVE HALF (§4.30). This is the case that failed for Ctrl+W
  // everywhere: the caret is in the tab strip, the sidebar or a rail view, no
  // surface is holding the keys, and the chord must mean the app action.
  "focus anywhere else does NOT - this is what makes Ctrl+W reachable at all",
  !ownsRawKeyboard(focusedInside("data-pane-leaf")),
);
check("nothing focused does not either", !ownsRawKeyboard(null));
check(
  "an editor pane does not own bare-Ctrl chords",
  !ownsRawKeyboard(focusedInside("data-editor-leaf-id")),
);

{
  // The selector is only a claim until something renders the attributes it
  // names. A marker renamed on the pane (or dropped from this list) leaves the
  // gate permanently OFF for that surface - silently, because the app chord it
  // then steals still "works". So read the panes back and require every
  // attribute named here to be on one of them.
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const read = (p: string) => readFileSync(join(root, p), "utf8");
  const panes = ["src/modules/terminal/TerminalPane.tsx", "src/modules/rdp/RdpPane.tsx"] as const;
  const rendered = panes.map((p) => stripComments(read(p))).join("\n");
  const markers = KEYBOARD_OWNING_SURFACES.split(",").map((s) => s.trim());
  check("the selector names at least the two known surfaces", markers.length >= 2, markers);
  for (const sel of markers) {
    const attr = /^\[([a-z-]+)\]$/.exec(sel)?.[1];
    check(`${sel} is a plain attribute selector`, attr !== undefined, sel);
    check(
      `${sel} is actually rendered by a pane (outside a comment)`,
      attr !== undefined && new RegExp(`${attr}=`).test(rendered),
      sel,
    );
  }
  check(
    "the terminal marker is on TerminalPane, not only somewhere in the tree",
    /data-terminal-leaf-id=/.test(stripComments(read(panes[0]))),
  );
  check(
    "and the RDP marker is on RdpPane",
    /data-rdp-leaf-id=/.test(stripComments(read(panes[1]))),
  );
}

console.log("\n[gate wiring] App asks focus and the rail view, not the active leaf kind");
{
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  // Stripped, and load-bearing: the gate's own comment block explains the fix by
  // NAMING `activeLeafKindCurrent === "terminal"`, so the "does NOT decide from
  // the active leaf kind" check below would fail against the correct code
  // without this - and the positive checks would pass against a gutted gate
  // whose expressions survived only as prose. Both directions, one stripper.
  const app = stripComments(readFileSync(join(root, "src/app/App.tsx"), "utf8"));
  const gate = /isDisabled:\s*\(id, e\) =>([\s\S]*?)\n\s*\}\);/.exec(app)?.[1] ?? "";
  check("found the isDisabled gate", gate !== "");
  check(
    "it calls ownsRawKeyboard on the event's own target",
    /ownsRawKeyboard\(focusTargetOf\(e\)\)/.test(gate),
  );
  check(
    // The straight revert, and the thing whose comment lied: leaf kind is not
    // focus, so a gate that reads it is the VLT-59 bug back again.
    "it does NOT decide from the active leaf kind",
    !/activeLeafKindCurrent/.test(gate),
    gate,
  );
  check(
    "a rail view turns the gate off, so its chords reach the app",
    /railView === null/.test(gate),
  );
  check("and Ctrl+D keeps its documented exemption", /id !== "pane\.splitRight"/.test(gate));
}

if (failed > 0) throw new Error(`${failed} check(s) failed`);
console.log("\nAll checks passed.");
