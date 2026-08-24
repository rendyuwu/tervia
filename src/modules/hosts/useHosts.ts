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

export function useHosts(): Map<string, Host> {
  const [hosts, setHosts] = useState<Map<string, Host>>(() => new Map());
  useEffect(() => {
    const load = () =>
      void listHosts().then((list) => setHosts(new Map(list.map((h) => [h.id, h]))));
    load();
    const unsub = onHostsChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);
  return hosts;
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
