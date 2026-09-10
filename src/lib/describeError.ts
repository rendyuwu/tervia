/**
 * Turn an unknown rejection into a sentence a user can read.
 *
 * ITS OWN MODULE, AND IT IMPORTS NOTHING, which is the whole reason it exists
 * here rather than beside its first caller. FOUR identical copies of these six
 * lines were live: the one `terminal/lib/session-helpers.ts` exports, a private
 * one each in `forwards/autostart.ts` and `forwards/controller.ts`, and a
 * function-local one inside `scripts/ssh-retry-verify.ts` - which was the
 * worst-placed of the four, because a check holding its own copy of the
 * function under test passes while the shipped one disagrees with it. The
 * copies were propagating by citation: that one's comment named
 * `controller.ts`'s copy as its precedent.
 * Neither of those could import the original - `session-helpers.ts` pulls in
 * `@xterm/xterm` and `@tauri-apps/plugin-os` at module scope, so it cannot even
 * be LOADED under `tsx`, and it also holds `wallpaperActive()`, which reads
 * `document`, so importing it would cost those two modules the "exercisable
 * under plain node" property their headers exist for. `src/lib/` sidesteps the
 * boundary entirely. `session-helpers.ts` re-exports this symbol, so its own
 * importers keep their spelling.
 *
 * THE STRING BRANCH IS LOAD-BEARING AND NOT BOILERPLATE. The forward commands
 * (`ssh_forward_open`, `ssh_forward_close`) reject with a RAW STRING, so that
 * arm is how the backend's own `ssh: bind 127.0.0.1:<port> failed: <io error>`
 * reaches a terminal banner or `bindFailureText` at all. Do not "simplify" the
 * body to `e instanceof Error`.
 *
 * `ssh_open` is this app's exception - it rejects with a `{kind, message}`
 * object - and `openSsh` rewraps a RECOGNISED one into an `Error` at its own
 * boundary, so no caller here meets one AS LONG AS the two kind sets agree.
 * They do today: `ssh/bridge.ts`'s `sshConnectErrorFrom` recognises the same
 * kinds `src-tauri/src/modules/ssh/session.rs` emits, and
 * `scripts/ssh-retry-verify.ts` pins that they stay matched. But the agreement
 * is not structural - anything `sshConnectErrorFrom` does not recognise it
 * returns unchanged, by design - so a kind added on one side only (a newer or
 * rolled-back backend, precisely the case that passthrough exists to survive)
 * arrives here as a raw object, and the `JSON.stringify` fallback below would
 * render `{"kind":"…","message":"…"}` into a banner or a toast.
 */
export function describeError(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}
