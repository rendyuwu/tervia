import { useEffect, useState } from "react";

import { listGroups, listHosts, onHostsChanged } from "./store";
import type { Host, HostGroup } from "./types";

// Saved hosts and groups, kept fresh across edits and across WINDOWS - the store
// broadcasts on every commit, so a rename in the settings webview reaches the tab
// strip without either side knowing about the other.
//
// One hook per collection rather than each surface loading by hand: every place
// that renders an `ssh:<name>` or `rdp:<name>` label needs the same map (the tab
// strip, the pane headers, the Workspaces panel), and loading it per surface is
// how one of them ends up showing a stale name after a rename.

/**
 * The saved hosts AND whether they have been read at least once.
 *
 * `loaded` DISTINGUISHES "NEVER READ" FROM "READ AND GENUINELY EMPTY", which
 * `hosts.size` by construction cannot. A consumer that treats an empty map as
 * "the hosts have not arrived yet" is right on the first frame of every mount
 * and wrong forever after for a user who has saved no hosts at all - and one
 * that treats it as "there are no hosts" is wrong the other way round, on the
 * first frame, every time. `ForwardRuleRow.hostDangling`
 * (`modules/forwards/page/derive.ts`) is the consumer that needs both answers
 * apart, and it is why this hook exists beside {@link useHosts}.
 *
 * NOTHING IN THE STORE LAYER CAN ANSWER THIS. `listHosts` returns `[]` for a
 * key that is absent and for a key holding an empty array alike, and
 * `ensureLoaded` is a startup entry point returning a recovery notice rather
 * than an observable flag. The fact lives in the CALLER's own async read: it is
 * exactly "has the first `listHosts()` settled", which is what the assignment
 * below records.
 *
 * `loaded` is written in the same state object as `hosts`, and only inside the
 * `.then`. Both halves matter. Written early - at render, or from a second
 * `useState` that a broadcast could set on its own - it would be true before
 * the first read lands, which reintroduces the first-frame flicker the
 * distinction exists to remove. And one object rather than two pieces of state
 * means a consumer can never observe `loaded` true beside a map from before the
 * read, or the reverse.
 */
export function useHostsSnapshot(): { hosts: Map<string, Host>; loaded: boolean } {
  const [snapshot, setSnapshot] = useState<{ hosts: Map<string, Host>; loaded: boolean }>(() => ({
    hosts: new Map(),
    loaded: false,
  }));
  useEffect(() => {
    const load = () =>
      void listHosts().then((list) =>
        setSnapshot({ hosts: new Map(list.map((h) => [h.id, h])), loaded: true }),
      );
    load();
    const unsub = onHostsChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);
  return snapshot;
}

/**
 * Just the map, for every surface that renders host names and has nothing to
 * say about a store that loaded empty. Delegates rather than loading again:
 * a second `useEffect` over the same store would be a second subscription and a
 * second chance to disagree with the first about what is saved. The map itself
 * is the state reference, so it stays stable BETWEEN renders and a `useMemo`
 * keyed on it does not refire.
 */
export function useHosts(): Map<string, Host> {
  return useHostsSnapshot().hosts;
}

export function useHostGroups(): HostGroup[] {
  const [groups, setGroups] = useState<HostGroup[]>([]);
  useEffect(() => {
    const load = () => void listGroups().then(setGroups);
    load();
    const unsub = onHostsChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);
  return groups;
}
