import { useEffect, useMemo, useState } from "react";

import { listRules, onForwardsChanged } from "./store";
import type { ForwardRule } from "./types";

// Kept fresh across edits and across WINDOWS - the store broadcasts on every
// commit, so a rule added in one window reaches a Hosts page in another without
// either side knowing about the other. Modelled on `modules/vault/useVault.ts`,
// which does the same for identities and keys.
//
// A MAP rather than an array because every caller looks a rule up by id - the
// Hosts page asks "does this host have forwards" per rendered card, and a list
// would make that a linear scan inside a render pass.

/**
 * Every saved forward rule, as one stable value.
 *
 * The `useMemo` is load-bearing rather than an optimisation, per
 * `useVault.ts:65-74`'s doc on the same shape: a consumer that lists this in a
 * `useMemo` dependency array would otherwise re-derive on every render, because
 * a Map handed back through a fresh wrapper is never `Object.is` the last one.
 * Wrapping the state value here rather than returning it directly is what keeps
 * that guarantee true even as this hook grows past a single `useState`, the way
 * `useVault`'s own two-collection shape already needed to.
 */
export function useForwards(): ReadonlyMap<string, ForwardRule> {
  const [rules, setRules] = useState<Map<string, ForwardRule>>(() => new Map());
  useEffect(() => {
    const load = () =>
      void listRules()
        .then((list) => setRules(new Map(list.map((r) => [r.id, r]))))
        .catch((err: unknown) => console.error("forwards: failed to load rules", err));
    load();
    const unsub = onForwardsChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);
  return useMemo(() => rules, [rules]);
}
