/**
 * Self-check for OSC 52 clipboard writes (`registerClipboardHandler`,
 * `muteOsc52ForReplay`). Run: `npx tsx scripts/terminal-osc52-verify.ts`.
 *
 * Runs the real xterm parser, because the properties below are about what
 * xterm hands the handler and what it answers on the PTY side:
 *  1. COPIES LAND DECODED: a well-formed copy reaches `onCopy` as the original
 *     UTF-8 text, for any target and either terminator; invalid, empty,
 *     separator-less and over-cap payloads never do.
 *  2. READS ARE NEVER ANSWERED: a `?` request produces no reply on `onData`,
 *     so a remote host cannot read the local clipboard.
 *  3. REPLAYS STAY HISTORY: copies inside a reattach's scrollback replay are
 *     skipped, while a live copy right after it still lands.
 */
/// <reference types="node" />
import type { Terminal as XTerm } from "@xterm/xterm";
import {
  OSC52_MAX_BYTES,
  registerClipboardHandler,
} from "../src/modules/terminal/lib/osc-handlers";

let failed = 0;
function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failed++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

// Deep-imported ESM build, as in `terminal-resize-verify`: the bare specifier
// resolves to the CJS `main` here and yields no named `Terminal`.
// @ts-expect-error TS7016 - no declaration file ships for this deep subpath
const { Terminal } = (await import("@xterm/xterm/lib/xterm.mjs")) as unknown as {
  Terminal: typeof XTerm;
};

// `pty-lifecycle`'s module graph reaches the settings store, which resolves the
// current webview window at import time, so it is imported dynamically, after
// this stand-in (static imports are hoisted above it). Same stand-in as
// `terminal-resize-verify`.
(globalThis as { window?: unknown }).window = {
  __TAURI_INTERNALS__: {
    metadata: { currentWindow: { label: "main" }, currentWebview: { label: "main" } },
    invoke: async () => undefined,
  },
};
const { muteOsc52ForReplay } = await import("../src/modules/terminal/lib/pty-lifecycle");
type Session = Parameters<typeof muteOsc52ForReplay>[0];

const feed = (t: XTerm, s: string) => new Promise<void>((r) => t.write(s, r));
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
const same = (a: string[], b: string[]) => JSON.stringify(a) === JSON.stringify(b);

const term = new Terminal({ cols: 20, rows: 5 });
let copies: string[] = [];
const replies: string[] = [];
registerClipboardHandler(term, (text) => copies.push(text));
term.onData((d) => replies.push(d));

async function copiesOf(seq: string): Promise<string[]> {
  copies = [];
  await feed(term, seq);
  return copies;
}

assert(
  same(await copiesOf(`\x1b]52;c;${b64("hello\nwörld ✓")}\x07`), ["hello\nwörld ✓"]),
  "a copy decodes to its multi-byte UTF-8 text",
);
assert(
  same(await copiesOf(`\x1b]52;;${b64("tmux")}\x1b\\`), ["tmux"]),
  "an empty target (tmux's default) with an ESC \\ terminator is copied",
);
assert(
  (await copiesOf("\x1b]52;c;?\x07")).length === 0 && replies.length === 0,
  "a read request copies nothing and is never answered",
);
assert((await copiesOf("\x1b]52;c;!!!\x07")).length === 0, "invalid base64 is ignored");
assert((await copiesOf("\x1b]52;c;\x07")).length === 0, "an empty payload is ignored");
assert((await copiesOf("\x1b]52;abc\x07")).length === 0, "a payload with no separator is ignored");

const atCap = await copiesOf(`\x1b]52;c;${b64("a".repeat(OSC52_MAX_BYTES))}\x07`);
assert(
  atCap.length === 1 && atCap[0].length === OSC52_MAX_BYTES,
  "a copy of exactly OSC52_MAX_BYTES is accepted",
);
assert(
  (await copiesOf(`\x1b]52;c;${b64("a".repeat(OSC52_MAX_BYTES + 1))}\x07`)).length === 0,
  "a copy one byte over OSC52_MAX_BYTES is dropped",
);

// Replay mute: the same gate `session-lifecycle` puts in front of the host write.
const rt = new Terminal({ cols: 20, rows: 5 });
const s = { term: rt, disposed: false, osc52Muted: false } as unknown as Session;
const got: string[] = [];
registerClipboardHandler(rt, (text) => {
  if (!s.osc52Muted) got.push(text);
});
const onData = muteOsc52ForReplay(s, (bytes) => rt.write(bytes));
const enc = new TextEncoder();
onData(enc.encode(`\x1b]52;c;${b64("replayed")}\x07`));
onData(enc.encode(`\x1b]52;c;${b64("live")}\x07`));
await feed(rt, "");
assert(
  same(got, ["live"]) && s.osc52Muted === false,
  "a reattach replay's copy is skipped, the next live copy lands, and the mute lifts",
);

// `throw` (not process.exit) for a non-zero exit, matching the other verify scripts.
if (failed > 0) throw new Error(`terminal-osc52-verify: ${failed} check(s) failed`);
console.log("\nterminal-osc52-verify: all checks passed");
