/**
 * The pane's pull policy: when a `frameReady` may start an `rdp_take_frame`, and
 * what the settle of a pull owes the loop.
 *
 * One credit is the backpressure - at most one pull in flight, so the backend
 * coalesces dirty rects between them - and a request that arrives while the credit
 * is taken is REMEMBERED rather than dropped. Dropping one is a freeze with no
 * second chance: the backend's signal is edge-triggered (a `frameReady` is emitted
 * only when a push finds the batcher empty), so the request the pane swallows is
 * the last word those rects get, and the pull that raced it can come back empty -
 * which used to schedule nothing, leaving the batcher dirty until an external
 * re-arm: a resize, a tab switch, a reconnect.
 *
 * Pure, and out of `RdpPane` for one reason: this is a state machine whose failure
 * is silent, and this suite has no renderer to drive one through.
 * `scripts/rdp-frame-verify.ts` walks the sequences that matter.
 */

export type PullGate = {
  /**
   * Ask for a pull. `true` = start one now. `false` = one is already in flight, in
   * which case the request is remembered and the next settle reports it.
   */
  request(): boolean;
  /**
   * Finish a pull. `true` = more to come (a non-empty batch, or a request made
   * while this one ran), so another pull has to follow. `false` = the loop is idle
   * until the next signal.
   */
  settle(painted: boolean): boolean;
};

/** A pull gate whose credit starts free. */
export function createPullGate(): PullGate {
  let inFlight = false;
  let wanted = false;
  return {
    request(): boolean {
      if (inFlight) {
        wanted = true;
        return false;
      }
      inFlight = true;
      return true;
    },
    settle(painted: boolean): boolean {
      inFlight = false;
      const again = painted || wanted;
      // Cleared before returning, so a signal that arrives while the next pull is
      // starting re-arms the loop instead of being absorbed by this one.
      wanted = false;
      return again;
    },
  };
}
