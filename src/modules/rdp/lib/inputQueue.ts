import type { RdpInputEvent } from "../bridge";

/**
 * Queue policy for input the backend refused.
 *
 * Kept pure and free of the Tauri bridge - the `import type` above is erased
 * at runtime - so the verify scripts can import it directly.
 */

/**
 * Keep only the newest of every run of consecutive moves.
 *
 * An absolute pointer position supersedes the one before it, so a run of moves
 * carries no more than its last entry. Nothing else is touched: a key
 * transition, a button, a wheel notch or a `releaseAll` is always kept, and a
 * run never collapses backwards past one of them. That is the property that
 * makes this safe to run over a re-queued batch - a discarded `keyUp` would
 * strand a modifier down on the server, a discarded move costs one frame of
 * cursor smoothing.
 */
export function coalesceMoves(events: RdpInputEvent[]): RdpInputEvent[] {
  return events.filter(
    (event, i) => event.kind !== "mouseMove" || events[i + 1]?.kind !== "mouseMove",
  );
}
