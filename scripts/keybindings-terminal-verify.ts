/**
 * Self-check for the raw-keyboard gate (`yieldsToRawKeyboard`), in its three
 * parts.
 *
 *  1. WHICH CHORDS - `isTerminalControlChord` / `isTerminalMetaChord`: the ones
 *     a focused terminal keeps (readline editing, Ctrl+D EOF / screen detach,
 *     Ctrl+I Tab, Ctrl+[ Esc, the tmux/screen prefix) instead of the app's
 *     Mod+letter shortcuts stealing them on Windows/Linux.
 *  2. WHO IS FOCUSED - `ownsRawKeyboard` (`shortcuts/lib/keyboardOwner.ts`).
 *     The half that was never asked: the gate used to test which leaf was
 *     ACTIVE IN THE TAB while its own comment claimed to be about focus, so
 *     Ctrl+W was suppressed with the caret in the tab strip (closing no tab
 *     anywhere) and Ctrl+T / Ctrl+] / Ctrl+[ were eaten by a terminal a rail
 *     view had made invisible. Both halves must hold for the gate to fire,
 *     so both halves get a positive AND a negative case here.
 *  3. EVERY CALLER, NOT JUST APP - `yieldsToRawKeyboard` itself, applied
 *     inside `useGlobalShortcuts` so no caller can forget it. FileExplorer's
 *     "Go to file" (Mod+P / Mod+G) collides with a focused terminal's
 *     readline Ctrl+P (previous-history) and Ctrl+G (abort), which is
 *     exactly the bug this gate exists to prevent: it had no gate of its
 *     own before this.
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
  yieldsToRawKeyboard,
  type FocusTarget,
} from "../src/modules/shortcuts/lib/keyboardOwner";
import { stripComments, stripperSelfTest } from "./lib/source";

type Ev = {
  code: string;
  ctrlKey?: boolean;
  shiftKey?: boolean;
  altKey?: boolean;
  metaKey?: boolean;
};
// The full KeyboardEvent-shaped fixture, defaulted then overridden - shared by
// `ev` below (which chords) and the gate checks further down (who is
// focused + every caller), so both sections build fixtures the same way.
const toEvent = (e: Ev): KeyboardEvent =>
  ({
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
    metaKey: false,
    ...e,
  }) as KeyboardEvent;
// Mirrors the "which chords" half of the gate: a focused terminal owns
// bare-Ctrl control codes AND bare-Alt meta sequences, so both fall through
// to xterm.
const ev = (e: Ev) => {
  const k = toEvent(e);
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
// The other two-thirds of the gate: who is holding the keys, and whether
// every caller actually asks.
// ---------------------------------------------------------------------------

// Self-test: both directions of the shared stripper's JSX-comment branch.
// Placed here rather than beside the import because `failed` is a `let` that
// `check` increments, and calling `check` before its initialiser runs would
// throw instead of reporting FAIL.
for (const t of stripperSelfTest()) check(t.label, t.ok);

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
  // An RDP pane owns Ctrl and Alt exactly as a terminal does,
  // so the selector has to name it too or every bare-Ctrl chord fires an app
  // action instead of reaching the remote desktop.
  "focus inside an RDP pane owns it too",
  ownsRawKeyboard(focusedInside("data-rdp-leaf-id")),
);
check(
  // THE NEGATIVE HALF. This is the case that failed for Ctrl+W
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

console.log("\n[yieldsToRawKeyboard] the exact rule the FileExplorer bug needed and did not have");
{
  const terminal = focusedInside("data-terminal-leaf-id");
  const rdp = focusedInside("data-rdp-leaf-id");
  const tabStrip = focusedInside("data-pane-leaf");
  const ctrlP = toEvent({ code: "KeyP", ctrlKey: true });
  const ctrlG = toEvent({ code: "KeyG", ctrlKey: true });

  check(
    // Both are explorer.search's default bindings (Go to file) - and also a
    // terminal's readline Ctrl+P (previous-history) and Ctrl+G (abort), which
    // is the whole bug: FileExplorer had no gate, so these two never reached
    // xterm.
    "Ctrl+P and Ctrl+G (explorer.search) yield to a focused terminal",
    yieldsToRawKeyboard("explorer.search", terminal, ctrlP, false) &&
      yieldsToRawKeyboard("explorer.search", terminal, ctrlG, false),
  );
  check(
    // THE ISSUE'S NEGATIVE CONTROL: focus is in the tab strip, not a raw-
    // keyboard surface, so Go to file must still open from there.
    "the same chords do NOT yield with focus in the tab strip",
    !yieldsToRawKeyboard("explorer.search", tabStrip, ctrlP, false) &&
      !yieldsToRawKeyboard("explorer.search", tabStrip, ctrlG, false),
  );
  check(
    "Ctrl+P also yields to a focused RDP pane",
    yieldsToRawKeyboard("explorer.search", rdp, ctrlP, false),
  );
  check(
    "a covered tab area (rail view open) turns the gate off even in a terminal",
    !yieldsToRawKeyboard("explorer.search", terminal, ctrlP, true),
  );
  check(
    "Ctrl+D (pane.splitRight) keeps its documented exemption and never yields",
    !yieldsToRawKeyboard(
      "pane.splitRight",
      terminal,
      toEvent({ code: "KeyD", ctrlKey: true }),
      false,
    ),
  );
  check(
    "a Shift chord (explorer.grep's Mod+Shift+F) is not a control chord, so it never yields",
    !yieldsToRawKeyboard(
      "explorer.grep",
      terminal,
      toEvent({ code: "KeyF", ctrlKey: true, shiftKey: true }),
      false,
    ),
  );
  check(
    // The meta half of the predicate (bare-Alt), otherwise never exercised by
    // a direct call to yieldsToRawKeyboard - every row above is a Ctrl chord.
    "Alt+Z (editor.toggleWordWrap) also yields, via the meta branch",
    yieldsToRawKeyboard(
      "editor.toggleWordWrap",
      terminal,
      toEvent({ code: "KeyZ", altKey: true }),
      false,
    ),
  );
}

console.log("\n[gate wiring] the hook applies the gate; railView reaches every caller");
{
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const read = (p: string) => stripComments(readFileSync(join(root, p), "utf8"));

  const hook = read("src/modules/shortcuts/lib/useGlobalShortcuts.ts");
  const hookGateCall =
    /yieldsToRawKeyboard\(\s*s\.id,\s*focusTargetOf\(e\),\s*e,\s*options\.tabAreaCovered,?\s*\)/;
  check(
    "the hook's onKey calls yieldsToRawKeyboard with the event's own target",
    hookGateCall.test(hook),
  );

  const app = read("src/app/App.tsx");
  const appGateCall = new RegExp(
    "useGlobalShortcuts\\(\\s*shortcutHandlers,\\s*\\{\\s*tabAreaCovered:\\s*" +
      "railView !== null,?\\s*\\},?\\s*\\)",
  );
  check(
    "App calls useGlobalShortcuts with tabAreaCovered derived from railView",
    appGateCall.test(app),
  );
}

if (failed > 0) throw new Error(`${failed} check(s) failed`);
console.log("\nAll checks passed.");
