/**
 * Shortcut-collision audit for Tervia. Verifies, for the Windows/Linux expansion
 * (Mod = Ctrl, the case where app chords can shadow shell control codes):
 *   A. No two DIFFERENT catalog actions share the same chord (intra-app clash).
 *   B. In a focused terminal (local PTY and SSH are the same "terminal" leaf),
 *      every shell control code reaches xterm instead of firing an app action:
 *      bare Ctrl+letter / Ctrl+[ / Ctrl+] / Ctrl+\ (via yieldsToRawKeyboard,
 *      the real gate), plus Enter / Ctrl+Enter / Shift+Enter (no global
 *      handler -> fall through) - except the three chords the gate hands to
 *      the app by design: Ctrl+D pane.splitRight, Ctrl+] pane.focusNext,
 *      Ctrl+[ pane.focusPrev.
 * Run: `npx tsx scripts/keybindings-collision-verify.ts`.
 *
 * Under node, platform() throws so MOD_PROP resolves to "ctrl" (see platform.ts),
 * i.e. this checks exactly the Windows/Linux bindings. macOS is safer by
 * construction: Mod = Cmd (meta), so no bare-Ctrl chord is ever an app shortcut.
 */
import { SHORTCUTS, type KeyBinding } from "../src/modules/shortcuts/shortcuts";
import { yieldsToRawKeyboard, type FocusTarget } from "../src/modules/shortcuts/lib/keyboardOwner";

// Actions with a global handler in src/app/lib/shortcutHandlers.ts. The
// readOnly Enter-family (ai.send / ai.queueWhileBusy / ai.newline) is NOT here:
// it is documentation-only and handled locally in the AI input, so those chords
// fall through globally (that is how Enter reaches the shell in a terminal).
const HANDLED = new Set<string>([
  "tab.new",
  "tab.newPreview",
  "tab.newEditor",
  "tab.newAgent",
  "tab.close",
  "tab.next",
  "tab.prev",
  "tab.selectByIndex",
  "pane.splitRight",
  "pane.splitDown",
  "pane.focusNext",
  "pane.focusPrev",
  "pane.splitBrowser",
  "browser.reload",
  "browser.back",
  "browser.forward",
  "browser.focusAddressBar",
  "search.focus",
  "editor.findReplace",
  "ai.toggle",
  "ai.askSelection",
  "scm.open",
  "shortcuts.open",
  "settings.open",
  "sidebar.toggle",
  "view.zoomIn",
  "view.zoomOut",
  "view.zoomReset",
  "editor.toggleWordWrap",
  "editor.formatDocument",
  "terminal.copy",
  "terminal.paste",
  "terminal.close",
]);

function canon(b: KeyBinding): string {
  const mods = [b.ctrl && "Ctrl", b.shift && "Shift", b.alt && "Alt", b.meta && "Meta"]
    .filter(Boolean)
    .join("+");
  return (mods ? mods + "+" : "") + b.key.toLowerCase();
}

// Map a binding's key to a KeyboardEvent.code so isTerminalControlChord (which
// reads e.code) sees what the browser would emit.
function keyToCode(key: string): string {
  if (/^[a-z]$/i.test(key)) return "Key" + key.toUpperCase();
  if (/^[0-9]$/.test(key)) return "Digit" + key;
  if (key === "[") return "BracketLeft";
  if (key === "]") return "BracketRight";
  if (key === "\\") return "Backslash";
  return key; // Tab, Enter, Escape, ArrowLeft, ... (not control-code producers)
}

function toEvent(b: KeyBinding): KeyboardEvent {
  return {
    ctrlKey: !!b.ctrl,
    shiftKey: !!b.shift,
    altKey: !!b.alt,
    metaKey: !!b.meta,
    code: keyToCode(b.key),
    key: b.key,
  } as KeyboardEvent;
}

let failed = 0;

// --- A. Intra-app duplicate chords ---------------------------------------
console.log("[A] intra-app duplicate chords (same key -> two actions; first in array wins)");
const byChord = new Map<string, string[]>();
for (const s of SHORTCUTS) {
  const bindings = s.defaultBindings;
  for (const b of bindings) {
    const c = canon(b);
    const arr = byChord.get(c) ?? [];
    arr.push(s.id);
    byChord.set(c, arr);
  }
}
let dupes = 0;
for (const [chord, ids] of byChord) {
  const distinct = [...new Set(ids)];
  if (distinct.length > 1) {
    console.error(`  CLASH: ${chord} -> ${distinct.join(", ")}`);
    dupes++;
    failed++;
  }
}
if (dupes === 0) console.log("  ok: no chord is bound to two different actions");

// --- B. Terminal focus: every shell control code must fall through ---------
console.log(
  "\n[B] terminal focus: shell control codes must reach xterm, except the chords the gate hands to the app by design",
);
// A focus target inside a terminal leaf, as `ownsRawKeyboard` asks it.
const TERMINAL: FocusTarget = {
  closest: (sel) => (sel.includes("[data-terminal-leaf-id]") ? {} : null),
};
// Which action (if any) fires for a chord when a terminal is focused. Mirrors
// useGlobalShortcuts (first match in array order wins) and calls its real
// raw-keyboard gate (yieldsToRawKeyboard, shortcuts/lib/keyboardOwner.ts).
function terminalAction(ev: KeyboardEvent): string | null {
  for (const s of SHORTCUTS) {
    const match = s.defaultBindings.some(
      (b) =>
        !!ev.ctrlKey === !!b.ctrl &&
        !!ev.shiftKey === !!b.shift &&
        !!ev.altKey === !!b.alt &&
        !!ev.metaKey === !!b.meta &&
        b.key.toLowerCase() === ev.key.toLowerCase(),
    );
    if (!match) continue;
    // The real gate: terminal focused + control/meta chord -> fall through,
    // unless the action fires over a raw-keyboard surface by design.
    if (yieldsToRawKeyboard(s.id, TERMINAL, ev, false)) return null;
    // browser.* is gated off outside a browser pane -> fall through.
    if (s.id.startsWith("browser.")) return null;
    // No global handler -> early return without preventDefault -> fall through.
    if (!HANDLED.has(s.id)) return null;
    return s.id; // captured: this app action fires, shell never sees the key
  }
  return null; // unbound -> reaches the shell
}

// The keys a shell/readline/tmux/screen actually needs to receive.
const SHELL_KEYS: KeyBinding[] = [
  ..."abcdefghijklmnopqrstuvwxyz".split("").map((k) => ({ key: k, ctrl: true })),
  { key: "[", ctrl: true },
  { key: "]", ctrl: true },
  { key: "\\", ctrl: true },
  { key: "Enter" },
  { key: "Enter", ctrl: true },
  { key: "Enter", shift: true },
  { key: "Tab" },
  { key: "Escape" },
  { key: "Backspace" },
  { key: "ArrowUp" },
  { key: "ArrowDown" },
  { key: "ArrowLeft" },
  { key: "ArrowRight" },
  // readline meta sequences (M-b/f/d/. word ops, M-1..9 digit-argument).
  { key: "b", alt: true },
  { key: "f", alt: true },
  { key: "d", alt: true },
  { key: "z", alt: true },
  { key: "1", alt: true },
];
// The chords the gate hands to the app over a focused terminal by design
// (keyboardOwner.ts FIRES_OVER_RAW_KEYBOARD), keyed by canon(binding).
const TAKEN_BY_DESIGN: Partial<Record<string, string>> = {
  "Ctrl+d": "pane.splitRight",
  "Ctrl+]": "pane.focusNext",
  "Ctrl+[": "pane.focusPrev",
};
let shadowed = 0;
for (const b of SHELL_KEYS) {
  const fired = terminalAction(toEvent(b));
  const expected = TAKEN_BY_DESIGN[canon(b)] ?? null;
  if (fired === expected) continue;
  if (fired) {
    console.error(`  SHADOWED: ${canon(b)} is eaten by ${fired} instead of reaching the shell`);
  } else {
    console.error(`  NOT TAKEN: ${canon(b)} should fire ${expected} but reaches the shell`);
  }
  shadowed++;
  failed++;
}
if (shadowed === 0)
  console.log(
    "  ok: every bare-Ctrl control code + Enter/Tab/Esc/arrows reaches the shell, except Ctrl+D / Ctrl+] / Ctrl+[ (app by design)",
  );

// --- Informational: app chords that still fire inside a terminal ----------
console.log(
  "\n[info] app chords that stay active INSIDE a terminal (Shift/Alt/Meta chords, plus the control chords the gate hands to the app by design):",
);
const active = new Set<string>();
for (const s of SHORTCUTS) {
  for (const b of s.defaultBindings) {
    const fired = terminalAction(toEvent(b));
    if (fired) active.add(`${canon(b)} -> ${fired}`);
  }
}
[...active].sort().forEach((x) => console.log("  " + x));

if (failed > 0) throw new Error(`${failed} collision issue(s) found`);
console.log(
  "\nAll checks passed: no clashes, terminal keeps every shell control code except the three chords the gate hands to the app by design.",
);
